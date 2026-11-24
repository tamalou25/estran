"""The five Threat-layer connectors, each translated from a real excerpt of its source."""

import gzip
import json

import httpx
import pytest
from support import served

from estran.collector.connectors import REGISTRY
from estran.collector.connectors.attack import AttackConnector
from estran.collector.connectors.certfr import CertFrAlertsConnector
from estran.collector.connectors.ctid import KevAttackMappingConnector
from estran.collector.connectors.epss import EpssConnector
from estran.collector.connectors.nvd import NvdConnector
from estran.collector.http import HttpClient
from estran.collector.sdk import ConnectorError
from estran.ontology import load_ontology, validate_link, validate_object, validate_properties


@pytest.fixture(scope="module")
def threat(fixtures_dir):
    return fixtures_dir / "threat"


@pytest.fixture(scope="module")
def ontology(ontology_path):
    return load_ontology(ontology_path)


def by_key(translation, type_id):
    return {o.key: o for o in translation.objects if o.type == type_id}


def links_of(translation, type_id):
    return {(link.source[1], link.target[1]) for link in translation.links if link.type == type_id}


def assert_fits_ontology(ontology, translation):
    for record in translation.objects:
        assert validate_object(ontology, record.type, record.properties) == record.properties
    for link in translation.links:
        validate_link(ontology, link.type, link.source[0], link.target[0])


# --- registry ---------------------------------------------------------------------------------


def test_a_source_always_runs_before_those_that_build_on_it():
    order = [cls.manifest.id for cls in REGISTRY.values()]

    for cls in REGISTRY.values():
        for needed in cls.manifest.after:
            assert order.index(needed) < order.index(cls.manifest.id)


def test_only_redistributable_sources_ship_a_snapshot():
    for cls in REGISTRY.values():
        assert cls.manifest.redistributable or cls.manifest.snapshot is None


# --- MITRE ATT&CK -----------------------------------------------------------------------------


@pytest.fixture(scope="module")
def attack(threat):
    return AttackConnector().translate((threat / "attack.json").read_bytes())


def test_attack_objects_are_keyed_by_their_public_identifier(attack):
    assert set(by_key(attack, "technique")) == {
        "T1003", "T1005", "T1046", "T1059", "T1078", "T1189", "T1190",
    }  # fmt: skip
    assert set(by_key(attack, "group")) == {"G0117", "G1017"}
    assert set(by_key(attack, "software")) == {"S0108", "S1154"}
    assert "TA0001" in by_key(attack, "tactic")


def test_retired_attack_objects_are_left_out(attack):
    assert "T1562" not in by_key(attack, "technique")  # deprecated since the mapping was made
    assert all(
        "T1562" not in pair for kind in ("group_uses_technique",) for pair in links_of(attack, kind)
    )


def test_technique_carries_its_description_without_citation_markers(attack):
    technique = by_key(attack, "technique")["T1190"]

    assert technique.title == "Exploit Public-Facing Application"
    assert technique.properties["url"] == "https://attack.mitre.org/techniques/T1190"
    assert technique.properties["is_subtechnique"] is False
    assert "(Citation:" not in technique.properties["description"]
    assert "platforms" in technique.properties


def test_group_keeps_its_other_names_and_software_its_nature(attack):
    group = by_key(attack, "group")["G1017"]
    assert group.title == "Volt Typhoon"
    assert group.title not in group.properties["aliases"]
    assert len(group.properties["aliases"]) >= 1
    software = by_key(attack, "software")
    assert software["S0108"].properties["kind"] == "tool"
    assert software["S1154"].properties["kind"] == "malware"


def test_attack_relations_become_typed_links(attack):
    assert ("T1190", "TA0001") in links_of(attack, "technique_in_tactic")
    assert links_of(attack, "group_uses_technique") & {("G0117", "T1190"), ("G1017", "T1190")}
    assert links_of(attack, "group_uses_software")
    assert links_of(attack, "software_uses_technique")


def test_subtechnique_is_linked_to_its_parent(threat):
    bundle = json.loads((threat / "attack.json").read_bytes())
    parent = next(
        o for o in bundle["objects"] if o.get("name") == "Command and Scripting Interpreter"
    )
    child = {
        **parent,
        "id": "attack-pattern--00000000-0000-4000-8000-000000000001",
        "name": "PowerShell",
        "x_mitre_is_subtechnique": True,
        "external_references": [
            {"source_name": "mitre-attack", "external_id": "T1059.001",
             "url": "https://attack.mitre.org/techniques/T1059/001"}
        ],
    }  # fmt: skip
    relation = {
        "type": "relationship", "id": "relationship--00000000-0000-4000-8000-000000000002",
        "relationship_type": "subtechnique-of", "source_ref": child["id"], "target_ref": parent["id"],
    }  # fmt: skip
    bundle["objects"] += [child, relation]

    translation = AttackConnector().translate(json.dumps(bundle).encode())

    assert ("T1059.001", "T1059") in links_of(translation, "subtechnique_of")
    assert by_key(translation, "technique")["T1059.001"].properties["is_subtechnique"] is True


def test_names_of_people_credited_by_the_source_are_never_collected(threat):
    bundle = json.loads((threat / "attack.json").read_bytes())
    for item in bundle["objects"]:
        item["x_mitre_contributors"] = ["Jeanne Dupont, Exemple SA"]
        item["x_mitre_modified_by_ref"] = "identity--someone"

    translation = AttackConnector().translate(json.dumps(bundle).encode())

    assert "Dupont" not in json.dumps([o.properties for o in translation.objects])


def test_attack_records_fit_the_ontology(attack, ontology):
    assert attack.objects and attack.links
    assert_fits_ontology(ontology, attack)


@pytest.mark.parametrize("raw", [b"<html>", b'{"type": "bundle"}', b"[]"])
def test_document_that_is_not_an_attack_bundle_is_an_error(raw):
    with pytest.raises(ConnectorError):
        AttackConnector().translate(raw)


# --- CVE -> technique mapping ------------------------------------------------------------------


@pytest.fixture(scope="module")
def mapping(threat):
    return KevAttackMappingConnector().translate((threat / "mapping.json").read_bytes())


def test_mapping_tells_how_a_vulnerability_is_exploited_from_what_it_then_allows(mapping):
    assert ("CVE-2024-34102", "T1190") in links_of(mapping, "exploited_via")
    assert ("CVE-2024-34102", "T1059") in links_of(mapping, "enables")
    assert ("CVE-2024-34102", "T1005") in links_of(mapping, "enables")
    assert ("CVE-2024-4671", "T1189") in links_of(mapping, "exploited_via")
    assert ("CVE-2024-34102", "T1190") not in links_of(mapping, "enables")


def test_mapping_creates_no_object_and_fits_the_ontology(mapping, ontology):
    assert mapping.objects == []
    assert_fits_ontology(ontology, mapping)


def test_unusable_mapping_entries_are_skipped_and_counted(threat):
    document = json.loads((threat / "mapping.json").read_bytes())
    document["mapping_objects"] += [
        {
            "capability_id": "CVE-2024-0001",
            "attack_object_id": "T1190",
            "mapping_type": "uncategorized",
        },
        {
            "capability_id": "not-a-cve",
            "attack_object_id": "T1190",
            "mapping_type": "primary_impact",
        },
        {
            "capability_id": "CVE-2024-0001",
            "attack_object_id": "DROP TABLE",
            "mapping_type": "primary_impact",
        },
        "nonsense",
    ]

    translation = KevAttackMappingConnector().translate(json.dumps(document).encode())

    assert translation.skipped == 4
    assert all(source != "CVE-2024-0001" for source, _ in links_of(translation, "enables"))


# --- NVD ---------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def nvd(threat):
    return list(NvdConnector().translate((threat / "nvd.json").read_bytes()).enrichments)


def test_nvd_adds_severity_to_known_vulnerabilities(nvd, threat, ontology):
    source = json.loads((threat / "nvd.json").read_bytes())["vulnerabilities"]
    expected = next(v["cve"] for v in source if v["cve"]["id"] == "CVE-2024-34102")
    metrics = expected["metrics"]["cvssMetricV31"]
    # the NVD's own analysis when there is one, otherwise the first score given
    metric = next((m for m in metrics if m["type"] == "Primary"), metrics[0])["cvssData"]

    record = next(r for r in nvd if r.key == "CVE-2024-34102")

    assert record.type == "vulnerability"
    assert record.properties == {
        "cvss_score": metric["baseScore"],
        "cvss_severity": metric["baseSeverity"].lower(),
        "cvss_version": "3.1",
        "cvss_vector": metric["vectorString"],
        "published": expected["published"][:10],
    }
    assert {r.key for r in nvd} == {v["cve"]["id"] for v in source}
    for r in nvd:
        assert validate_properties(ontology, r.type, r.properties) == r.properties


def test_nvd_prefers_the_most_recent_scoring_system_it_has(threat):
    document = json.loads((threat / "nvd.json").read_bytes())
    cve = document["vulnerabilities"][0]["cve"]
    cve["metrics"] = {
        "cvssMetricV2": [{"type": "Primary", "baseSeverity": "HIGH",
                          "cvssData": {"version": "2.0", "vectorString": "AV:N", "baseScore": 7.5}}],
    }  # fmt: skip

    [record] = [
        r
        for r in NvdConnector().translate(json.dumps(document).encode()).enrichments
        if r.key == cve["id"]
    ]

    assert (record.properties["cvss_version"], record.properties["cvss_severity"]) == (
        "2.0",
        "high",
    )


def test_nvd_pages_are_fetched_politely_and_merged(threat):
    page = json.loads((threat / "nvd.json").read_bytes())
    entries = page["vulnerabilities"]
    asked: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        start = int(request.url.params.get("startIndex", "0"))
        asked.append(str(request.url))
        body = {**page, "totalResults": len(entries), "startIndex": start, "resultsPerPage": 2,
                "vulnerabilities": entries[start : start + 2]}  # fmt: skip
        return served(json.dumps(body).encode())

    connector = NvdConnector()
    connector.page_size = 2
    connector.pause_seconds = 0
    client = HttpClient(connector.manifest.domains, transport=httpx.MockTransport(handler))

    result = connector.fetch(client, None)

    assert len(asked) == 3
    assert all("hasKev" in url for url in asked)
    merged = list(connector.translate(result.content).enrichments)
    assert {r.key for r in merged} == {v["cve"]["id"] for v in entries}


def test_nvd_never_asks_more_often_than_its_public_rate_limit():
    assert NvdConnector.pause_seconds >= 6  # 5 requests per 30 seconds without a key


# --- EPSS --------------------------------------------------------------------------------------


def test_epss_scores_every_cve_of_the_file_with_the_date_of_the_model(threat, ontology):
    records = list(EpssConnector().translate((threat / "epss.csv.gz").read_bytes()).enrichments)

    record = next(r for r in records if r.key == "CVE-2024-34102")
    assert record.properties == {
        "epss_score": 0.97,
        "epss_percentile": 0.99,
        "epss_date": "2026-11-23",
    }
    assert len(records) == 8
    for r in records:
        assert validate_properties(ontology, r.type, r.properties) == r.properties


def test_epss_row_with_a_bad_score_is_caught_by_the_ontology(ontology):
    raw = gzip.compress(
        b"#model_version:v1,score_date:2026-11-23T12:00:23Z\ncve,epss,percentile\nCVE-2024-0001,high,0.5\n"
    )

    [record] = EpssConnector().translate(raw).enrichments

    with pytest.raises(ValueError, match="epss_score"):
        validate_properties(ontology, record.type, record.properties)


@pytest.mark.parametrize(
    "raw",
    [
        b"not gzip at all",
        gzip.compress(b"cve,score\nCVE-2024-0001,0.1\n"),
        gzip.compress(b""),
    ],
)
def test_epss_file_with_an_unexpected_layout_is_an_error(raw):
    with pytest.raises(ConnectorError):
        list(EpssConnector().translate(raw).enrichments)


# --- CERT-FR -----------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def certfr(threat):
    return CertFrAlertsConnector().translate((threat / "certfr_alertes.xml").read_bytes())


def test_each_alert_becomes_an_object_with_its_date_and_address(certfr, ontology):
    alerts = by_key(certfr, "alert")

    assert set(alerts) == {"CERTFR-2024-ALE-010", "CERTFR-2024-ALE-011", "CERTFR-2015-ALE-009"}
    alert = alerts["CERTFR-2015-ALE-009"]
    assert alert.title == "Vulnérabilité dans Apple Mac OS X"
    assert alert.properties["published"] == "2015-07-24"
    assert alert.properties["url"] == "https://www.cert.cyber.gouv.fr/alerte/CERTFR-2015-ALE-009/"
    assert alert.properties["description"].startswith("Une vulnérabilité a été découverte")
    assert_fits_ontology(ontology, certfr)


def test_alert_is_linked_to_every_cve_it_names(certfr):
    mentions = links_of(certfr, "alert_mentions")

    assert ("CERTFR-2024-ALE-011", "CVE-2024-40766") in mentions
    assert {"CVE-2024-42008", "CVE-2024-42009"} <= {
        cve for alert, cve in mentions if alert == "CERTFR-2024-ALE-010"
    }
    assert not any(alert == "CERTFR-2015-ALE-009" for alert, _ in mentions)


def test_feed_item_pointing_outside_the_cert_fr_site_is_skipped(threat):
    feed = (threat / "certfr_alertes.xml").read_text(encoding="utf-8")
    hostile = feed.replace(
        "https://www.cert.cyber.gouv.fr/alerte/CERTFR-2024-ALE-011/",
        "https://evil.example.com/alerte/CERTFR-2024-ALE-011/",
    )

    translation = CertFrAlertsConnector().translate(hostile.encode())

    assert "CERTFR-2024-ALE-011" not in by_key(translation, "alert")
    assert translation.skipped == 1


XML_BOMB = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>
<rss><channel><item><title>&lol2;</title></item></channel></rss>"""


@pytest.mark.parametrize("raw", [b"not xml", b"<html></html>", XML_BOMB])
def test_feed_that_is_not_a_plain_rss_document_is_an_error(raw):
    with pytest.raises(ConnectorError):
        CertFrAlertsConnector().translate(raw)
