import json
from pathlib import Path

import httpx
import pytest
from sqlalchemy import Engine, text
from support import served

from estran.collector.connectors.kev import KevConnector
from estran.collector.http import HttpClient
from estran.collector.runner import run_connector
from estran.collector.sdk import Connector, LinkRecord, ObjectRecord, Translation


def count(engine: Engine, table: str, where: str = "true") -> int:
    with engine.connect() as connection:
        return connection.execute(text(f"SELECT count(*) FROM {table} WHERE {where}")).scalar_one()


def rows(engine: Engine, sql: str, **params) -> list[dict]:
    with engine.connect() as connection:
        return [dict(row) for row in connection.execute(text(sql), params).mappings()]


def client_answering(handler) -> HttpClient:
    return HttpClient(KevConnector.manifest.domains, transport=httpx.MockTransport(handler))


# --- snapshot mode ------------------------------------------------------------------------


def test_snapshot_run_loads_objects_links_and_their_source(engine, ontology, snapshot_dir):
    result = run_connector(
        engine, ontology, KevConnector(), mode="snapshot", snapshot_dir=snapshot_dir
    )

    assert result.status == "success"
    assert count(engine, "objects", "type = 'vulnerability'") == 5
    assert count(engine, "objects", "type = 'product'") == 4
    assert count(engine, "objects", "type = 'vendor'") == 3
    assert count(engine, "links", "type = 'affects'") == 5
    assert count(engine, "links", "type = 'made_by'") == 4
    [source] = rows(engine, "SELECT * FROM sources")
    assert source["id"] == "cisa-kev"
    assert source["licence"] == "CC0 1.0"
    assert source["redistributable"] is True


def test_run_is_recorded_with_its_counts(engine, ontology, snapshot_dir):
    run_connector(engine, ontology, KevConnector(), mode="snapshot", snapshot_dir=snapshot_dir)

    [run] = rows(engine, "SELECT * FROM runs")
    assert run["source_id"] == "cisa-kev"
    assert run["mode"] == "snapshot"
    assert run["status"] == "success"
    assert (run["objects_count"], run["links_count"], run["skipped_count"]) == (12, 9, 0)
    assert run["finished_at"] >= run["started_at"]
    assert len(run["content_sha256"]) == 64
    assert run["error"] is None


def test_every_object_and_link_knows_which_source_provided_it(engine, ontology, snapshot_dir):
    run_connector(engine, ontology, KevConnector(), mode="snapshot", snapshot_dir=snapshot_dir)

    assert count(engine, "provenance", "object_id IS NOT NULL") == 12
    assert count(engine, "provenance", "link_id IS NOT NULL") == 9
    [provenance] = rows(
        engine,
        "SELECT p.* FROM provenance p JOIN objects o ON o.id = p.object_id "
        "WHERE o.key = 'CVE-2024-10441'",
    )
    assert provenance["source_id"] == "cisa-kev"
    assert "kev_date_added" in provenance["fields"]
    assert "name" in provenance["fields"]


def test_objects_can_be_found_by_their_searchable_text(engine, ontology, snapshot_dir):
    run_connector(engine, ontology, KevConnector(), mode="snapshot", snapshot_dir=snapshot_dir)

    [row] = rows(engine, "SELECT search_text FROM objects WHERE key = 'CVE-2024-10441'")
    assert "cve-2024-10441" in row["search_text"]
    assert "synology" in row["search_text"]


# --- running again ------------------------------------------------------------------------


def test_second_run_on_unchanged_content_creates_no_duplicate(engine, ontology, snapshot_dir):
    connector = KevConnector()
    run_connector(engine, ontology, connector, mode="snapshot", snapshot_dir=snapshot_dir)

    second = run_connector(engine, ontology, connector, mode="snapshot", snapshot_dir=snapshot_dir)

    assert second.status == "unchanged"
    assert count(engine, "objects") == 12
    assert count(engine, "links") == 9
    assert count(engine, "provenance") == 21
    assert count(engine, "runs") == 2


def test_changed_entry_updates_the_object_in_place(engine, ontology, snapshot_dir):
    connector = KevConnector()
    run_connector(engine, ontology, connector, mode="snapshot", snapshot_dir=snapshot_dir)
    [before] = rows(engine, "SELECT * FROM objects WHERE key = 'CVE-2024-10441'")

    catalog = json.loads((snapshot_dir / "kev.json").read_text(encoding="utf-8"))
    entry = next(v for v in catalog["vulnerabilities"] if v["cveID"] == "CVE-2024-10441")
    entry["vulnerabilityName"] = "Renamed vulnerability"
    entry["knownRansomwareCampaignUse"] = "Unknown"
    (snapshot_dir / "kev.json").write_text(json.dumps(catalog), encoding="utf-8")
    result = run_connector(engine, ontology, connector, mode="snapshot", snapshot_dir=snapshot_dir)

    assert result.status == "success"
    [after] = rows(engine, "SELECT * FROM objects WHERE key = 'CVE-2024-10441'")
    assert after["id"] == before["id"]
    assert after["title"] == "Renamed vulnerability"
    assert after["properties"]["ransomware_use"] == "unknown"
    assert after["first_seen"] == before["first_seen"]
    assert after["last_seen"] > before["last_seen"]
    assert count(engine, "objects") == 12
    assert count(engine, "provenance") == 21


# --- live mode ----------------------------------------------------------------------------


def test_live_run_downloads_from_the_declared_url(engine, ontology, snapshot_dir, fixtures_dir):
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return served((fixtures_dir / "kev_sample.json").read_bytes())

    result = run_connector(
        engine,
        ontology,
        KevConnector(),
        mode="live",
        snapshot_dir=snapshot_dir,
        client=client_answering(handler),
    )

    assert result.status == "success"
    assert requested == [KevConnector.manifest.url]
    assert count(engine, "objects", "type = 'vulnerability'") == 5
    [run] = rows(engine, "SELECT mode FROM runs")
    assert run["mode"] == "live"


def test_live_run_sends_the_last_etag_and_respects_not_modified(
    engine, ontology, snapshot_dir, fixtures_dir
):
    etags: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        etags.append(request.headers.get("If-None-Match"))
        if request.headers.get("If-None-Match") == '"v1"':
            return httpx.Response(304)
        return served((fixtures_dir / "kev_sample.json").read_bytes(), headers={"ETag": '"v1"'})

    client = client_answering(handler)
    connector = KevConnector()
    run_connector(
        engine, ontology, connector, mode="live", snapshot_dir=snapshot_dir, client=client
    )
    second = run_connector(
        engine, ontology, connector, mode="live", snapshot_dir=snapshot_dir, client=client
    )

    assert etags == [None, '"v1"']
    assert second.status == "unchanged"
    assert count(engine, "objects") == 12


def test_first_live_run_falls_back_to_the_snapshot_when_the_source_is_down(
    engine, ontology, snapshot_dir
):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    result = run_connector(
        engine,
        ontology,
        KevConnector(),
        mode="live",
        snapshot_dir=snapshot_dir,
        client=client_answering(handler),
    )

    assert result.status == "success"
    assert count(engine, "objects", "type = 'vulnerability'") == 5
    [run] = rows(engine, "SELECT mode, error FROM runs")
    assert run["mode"] == "snapshot"
    assert "503" in run["error"]


def test_failed_live_run_keeps_the_data_already_collected(engine, ontology, snapshot_dir):
    connector = KevConnector()
    run_connector(engine, ontology, connector, mode="snapshot", snapshot_dir=snapshot_dir)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    result = run_connector(
        engine,
        ontology,
        connector,
        mode="live",
        snapshot_dir=snapshot_dir,
        client=client_answering(handler),
    )

    assert result.status == "failed"
    assert count(engine, "objects") == 12
    [run] = rows(engine, "SELECT status, error FROM runs ORDER BY id DESC LIMIT 1")
    assert run["status"] == "failed"
    assert "503" in run["error"]


def test_unusable_document_fails_the_run_without_touching_the_data(engine, ontology, snapshot_dir):
    connector = KevConnector()
    run_connector(engine, ontology, connector, mode="snapshot", snapshot_dir=snapshot_dir)

    def handler(request: httpx.Request) -> httpx.Response:
        return served(b"<html>maintenance</html>")

    result = run_connector(
        engine,
        ontology,
        connector,
        mode="live",
        snapshot_dir=snapshot_dir,
        client=client_answering(handler),
    )

    assert result.status == "failed"
    assert count(engine, "objects") == 12


# --- the ontology is enforced on the way in -------------------------------------------------


class _SloppyConnector(Connector):
    """Emits one valid vendor, one object that breaks the ontology, and links to both."""

    manifest = KevConnector.manifest.model_copy(update={"id": "sloppy", "snapshot": "sloppy.bin"})

    def translate(self, raw: bytes) -> Translation:
        return Translation(
            objects=[
                ObjectRecord("vendor", "acme", "Acme", {"name": "Acme"}),
                ObjectRecord("product", "acme:rocket", "Rocket", {"name": "Rocket"}),
                ObjectRecord("product", "acme:spy", "Spy", {"name": "Spy", "owner": "someone"}),
                ObjectRecord("spaceship", "x", "X", {}),
            ],
            links=[
                LinkRecord("made_by", ("product", "acme:rocket"), ("vendor", "acme")),
                LinkRecord("made_by", ("product", "acme:spy"), ("vendor", "acme")),
                LinkRecord("made_by", ("vendor", "acme"), ("product", "acme:rocket")),
            ],
            skipped=1,
        )


@pytest.fixture
def sloppy_snapshot(tmp_path: Path) -> Path:
    (tmp_path / "sloppy.bin").write_bytes(b"anything")
    return tmp_path


def test_records_that_break_the_ontology_never_reach_the_database(
    engine, ontology, sloppy_snapshot
):
    result = run_connector(
        engine, ontology, _SloppyConnector(), mode="snapshot", snapshot_dir=sloppy_snapshot
    )

    assert result.status == "success"
    assert {row["key"] for row in rows(engine, "SELECT key FROM objects")} == {
        "acme",
        "acme:rocket",
    }
    assert count(engine, "links") == 1
    # 1 reported by the connector + 2 invalid objects + 2 invalid links
    [run] = rows(engine, "SELECT objects_count, links_count, skipped_count FROM runs")
    assert (run["objects_count"], run["links_count"], run["skipped_count"]) == (2, 1, 5)


def test_a_second_source_adds_its_fields_without_erasing_the_first(
    engine, ontology, snapshot_dir, tmp_path
):
    run_connector(engine, ontology, KevConnector(), mode="snapshot", snapshot_dir=snapshot_dir)

    class _Enricher(_SloppyConnector):
        manifest = KevConnector.manifest.model_copy(
            update={"id": "enricher", "snapshot": "enricher.bin"}
        )

        def translate(self, raw: bytes) -> Translation:
            return Translation(
                objects=[
                    ObjectRecord(
                        "vulnerability",
                        "CVE-2024-10441",
                        "Synology DSM",
                        {"name": "Synology DSM", "notes": "seen elsewhere"},
                    )
                ]
            )

    (tmp_path / "enricher.bin").write_bytes(b"anything")
    run_connector(engine, ontology, _Enricher(), mode="snapshot", snapshot_dir=tmp_path)

    [row] = rows(engine, "SELECT properties FROM objects WHERE key = 'CVE-2024-10441'")
    assert row["properties"]["notes"] == "seen elsewhere"
    assert row["properties"]["kev_date_added"] == "2026-11-18"
    sources = rows(
        engine,
        "SELECT p.source_id FROM provenance p JOIN objects o ON o.id = p.object_id "
        "WHERE o.key = 'CVE-2024-10441' ORDER BY p.source_id",
    )
    assert [row["source_id"] for row in sources] == ["cisa-kev", "enricher"]
