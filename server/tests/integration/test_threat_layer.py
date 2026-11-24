"""The whole Threat layer: six sources loaded in registry order, then followed like an analyst."""

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from support import served

from estran.api.main import create_app
from estran.collector.connectors import REGISTRY
from estran.collector.http import HttpClient
from estran.collector.runner import run_connector

FIXTURE_OF = {
    "cisa-kev": "kev.json",
    "mitre-attack": "attack.json",
    "ctid-kev-attack": "mapping.json",
    "nist-nvd": "nvd.json",
    "first-epss": "epss.csv.gz",
    "cert-fr-alertes": "certfr_alertes.xml",
}


@pytest.fixture
def loaded(engine, ontology, fixtures_dir, tmp_path) -> dict[str, object]:
    """Run every connector live against a fake Internet that serves the recorded excerpts."""
    results = {}
    for cls in REGISTRY.values():
        connector = cls()
        if not connector.is_configured():
            continue  # optional source without its key: the scheduler skips it too
        body = (fixtures_dir / "threat" / FIXTURE_OF[connector.manifest.id]).read_bytes()
        client = HttpClient(
            connector.manifest.domains,
            transport=httpx.MockTransport(lambda request, body=body: served(body)),
        )
        if hasattr(connector, "pause_seconds"):
            connector.pause_seconds = 0
        results[connector.manifest.id] = run_connector(
            engine, ontology, connector, mode="live", snapshot_dir=tmp_path, client=client
        )
    return results


@pytest.fixture
def api(loaded, engine, ontology) -> TestClient:
    return TestClient(create_app(engine=engine, ontology=ontology))


def neighbors(api: TestClient, type_id: str, key: str) -> set[tuple[str, str, str]]:
    body = api.get(f"/api/objects/{type_id}/{key}/neighbors", params={"limit": 200}).json()
    return {(n["link_type"], n["direction"], n["object"]["key"]) for n in body["items"]}


def test_every_source_loads(loaded):
    assert {source: result.status for source, result in loaded.items()} == dict.fromkeys(
        FIXTURE_OF, "success"
    )


def test_from_a_vulnerability_to_the_groups_that_could_use_it(api):
    """The demonstration thread: CVE -> how it is exploited -> who works that way."""
    cve = neighbors(api, "vulnerability", "CVE-2024-34102")
    assert ("exploited_via", "out", "T1190") in cve
    assert ("enables", "out", "T1059") in cve

    technique = neighbors(api, "technique", "T1190")
    assert ("exploited_via", "in", "CVE-2024-34102") in technique
    assert ("technique_in_tactic", "out", "TA0001") in technique
    groups = {key for kind, direction, key in technique if kind == "group_uses_technique"}
    assert groups & {"G0117", "G1017"}

    # one more step: the software a group of the excerpt is known to use
    volt_typhoon = neighbors(api, "group", "G1017")
    assert any(kind == "group_uses_software" for kind, _, _ in volt_typhoon)


def test_a_short_list_of_neighbours_shows_every_kind_of_relation(api):
    """T1190 has vulnerabilities, groups and a tactic around it: three neighbours must not be
    three vulnerabilities, or the groups would stay hidden behind them."""
    body = api.get("/api/objects/technique/T1190/neighbors", params={"limit": 3}).json()

    kinds = [(n["link_type"], n["direction"]) for n in body["items"]]
    assert len(set(kinds)) == 3
    assert body["total"] > 3
    assert ("group_uses_technique", "in") in kinds


def test_neighbours_are_all_reachable_page_after_page(api):
    everything = api.get("/api/objects/technique/T1059/neighbors", params={"limit": 200}).json()
    paged = []
    for offset in range(0, everything["total"], 2):
        page = api.get(
            "/api/objects/technique/T1059/neighbors", params={"limit": 2, "offset": offset}
        ).json()
        paged += [(n["link_type"], n["direction"], n["object"]["key"]) for n in page["items"]]

    assert len(paged) == everything["total"] == len(set(paged))


def test_vulnerability_gathers_what_four_sources_say_about_it(api):
    body = api.get("/api/objects/vulnerability/CVE-2024-34102").json()

    properties = body["properties"]
    assert properties["kev_date_added"]  # CISA KEV
    assert properties["cvss_severity"] in {"critical", "high", "medium", "low"}  # NVD
    assert properties["epss_score"] == 0.97  # EPSS
    assert properties["epss_date"] == "2026-11-23"
    sources = {p["source"]["id"]: p["fields"] for p in body["provenance"]}
    assert set(sources) == {"cisa-kev", "nist-nvd", "first-epss"}
    assert "epss_score" in sources["first-epss"]
    assert "cvss_score" in sources["nist-nvd"]
    assert "epss_score" not in sources["cisa-kev"]


def test_alert_points_to_the_exploited_vulnerability_it_names(api):
    alert = neighbors(api, "alert", "CERTFR-2024-ALE-011")

    assert ("alert_mentions", "out", "CVE-2024-40766") in alert
    assert ("alert_mentions", "in", "CERTFR-2024-ALE-011") in neighbors(
        api, "vulnerability", "CVE-2024-40766"
    )


def test_what_cannot_be_linked_is_counted_not_invented(loaded, engine):
    # the mapping names a technique retired from ATT&CK; one alert names a CVE Estran lacks
    assert loaded["ctid-kev-attack"].skipped == 1
    assert loaded["cert-fr-alertes"].skipped == 1
    with engine.connect() as connection:
        ghosts = connection.execute(
            text("SELECT count(*) FROM objects WHERE key IN ('T1562', 'CVE-2024-42008')")
        ).scalar_one()
    assert ghosts == 0


def test_vulnerabilities_can_be_sorted_and_filtered_on_the_added_scores(api):
    by_epss = api.get(
        "/api/objects", params={"type": "vulnerability", "sort": "epss_score", "order": "desc"}
    ).json()["items"]
    scores = [item["properties"]["epss_score"] for item in by_epss]
    assert scores == sorted(scores, reverse=True)
    assert by_epss[0]["key"] == "CVE-2024-34102"

    critical = api.get(
        "/api/objects", params={"type": "vulnerability", "filter": "cvss_severity:critical"}
    ).json()
    assert all(i["properties"]["cvss_severity"] == "critical" for i in critical["items"])


def test_group_is_found_by_one_of_its_other_names(api):
    group = api.get("/api/objects/group/G1017").json()
    alias = group["properties"]["aliases"][0]

    found = api.get("/api/objects", params={"type": "group", "q": alias.lower()}).json()

    assert "G1017" in [item["key"] for item in found["items"]]


def test_sources_show_the_notice_their_licence_requires(api):
    sources = {source["id"]: source for source in api.get("/api/sources").json()}

    assert "not endorsed or certified by the NVD" in sources["nist-nvd"]["attribution"]
    assert "The MITRE Corporation" in sources["mitre-attack"]["attribution"]
    assert sources["first-epss"]["redistributable"] is False
