"""A source can add fields to objects another source created, without creating objects itself."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine, text

from estran.collector.connectors.kev import KevConnector
from estran.collector.runner import run_connector
from estran.collector.sdk import Connector, EnrichmentRecord, LinkRecord, Translation


def rows(engine: Engine, sql: str, **params) -> list[dict]:
    with engine.connect() as connection:
        return [dict(row) for row in connection.execute(text(sql), params).mappings()]


class _Scores(Connector):
    """Like EPSS: a score for every CVE that exists in the world, known to Estran or not."""

    manifest = KevConnector.manifest.model_copy(
        update={
            "id": "scores",
            "snapshot": "scores.bin",
            "after": ["cisa-kev"],
            "enriches": ["vulnerability"],
        }
    )

    def translate(self, raw: bytes) -> Translation:
        def enrichments() -> Iterator[EnrichmentRecord]:
            yield EnrichmentRecord("vulnerability", "CVE-2024-10441", {"epss_score": 0.91})
            yield EnrichmentRecord("vulnerability", "CVE-2026-59310", {"epss_score": 0.02})
            yield EnrichmentRecord("vulnerability", "CVE-1999-0001", {"epss_score": 0.5})  # unknown
            yield EnrichmentRecord("vulnerability", "CVE-2026-41709", {"epss_score": "n/a"})  # bad
            yield EnrichmentRecord("vulnerability", "CVE-2026-90817", {"owner": "x"})  # bad

        return Translation(enrichments=enrichments())


@pytest.fixture
def scores_dir(tmp_path: Path) -> Path:
    (tmp_path / "scores.bin").write_bytes(b"v1")
    return tmp_path


@pytest.fixture
def kev_loaded(engine, ontology, snapshot_dir) -> None:
    run_connector(engine, ontology, KevConnector(), mode="snapshot", snapshot_dir=snapshot_dir)


def test_enrichment_adds_fields_to_existing_objects(engine, ontology, kev_loaded, scores_dir):
    result = run_connector(engine, ontology, _Scores(), mode="snapshot", snapshot_dir=scores_dir)

    assert result.status == "success"
    [row] = rows(engine, "SELECT properties FROM objects WHERE key = 'CVE-2024-10441'")
    assert row["properties"]["epss_score"] == 0.91
    assert row["properties"]["kev_date_added"] == "2026-11-18"  # the first source's data stays


def test_enrichment_never_creates_objects(engine, ontology, kev_loaded, scores_dir):
    run_connector(engine, ontology, _Scores(), mode="snapshot", snapshot_dir=scores_dir)

    assert rows(engine, "SELECT count(*) AS n FROM objects")[0]["n"] == 12
    assert (
        rows(engine, "SELECT count(*) AS n FROM objects WHERE key = 'CVE-1999-0001'")[0]["n"] == 0
    )


def test_invalid_enrichment_is_skipped_and_counted_but_unknown_objects_are_not_errors(
    engine, ontology, kev_loaded, scores_dir
):
    run_connector(engine, ontology, _Scores(), mode="snapshot", snapshot_dir=scores_dir)

    [run] = rows(engine, "SELECT * FROM runs WHERE source_id = 'scores'")
    # 2 objects enriched; 2 invalid values skipped; the CVE Estran does not know is just ignored
    assert (run["objects_count"], run["skipped_count"]) == (2, 2)
    [row] = rows(engine, "SELECT properties FROM objects WHERE key = 'CVE-2026-41709'")
    assert "epss_score" not in row["properties"]


def test_enriched_object_remembers_both_sources(engine, ontology, kev_loaded, scores_dir):
    run_connector(engine, ontology, _Scores(), mode="snapshot", snapshot_dir=scores_dir)

    provenance = rows(
        engine,
        "SELECT p.source_id, p.fields FROM provenance p JOIN objects o ON o.id = p.object_id "
        "WHERE o.key = 'CVE-2024-10441' ORDER BY p.source_id",
    )
    assert [p["source_id"] for p in provenance] == ["cisa-kev", "scores"]
    assert provenance[1]["fields"] == ["epss_score"]


def test_enrichment_before_the_objects_exist_changes_nothing(engine, ontology, scores_dir):
    result = run_connector(engine, ontology, _Scores(), mode="snapshot", snapshot_dir=scores_dir)

    assert result.status == "success"
    assert rows(engine, "SELECT count(*) AS n FROM objects")[0]["n"] == 0


def test_forced_run_reloads_identical_content(engine, ontology, snapshot_dir, scores_dir):
    """New objects appeared since the last run: the same scores file must be applied again."""
    connector = _Scores()
    run_connector(engine, ontology, connector, mode="snapshot", snapshot_dir=scores_dir)
    run_connector(engine, ontology, KevConnector(), mode="snapshot", snapshot_dir=snapshot_dir)

    unforced = run_connector(engine, ontology, connector, mode="snapshot", snapshot_dir=scores_dir)
    forced = run_connector(
        engine, ontology, connector, mode="snapshot", snapshot_dir=scores_dir, force=True
    )

    assert unforced.status == "unchanged"
    assert forced.status == "success"
    [row] = rows(engine, "SELECT properties FROM objects WHERE key = 'CVE-2024-10441'")
    assert row["properties"]["epss_score"] == 0.91


class _Mapping(Connector):
    """Like the CVE -> technique mapping: only links, between objects owned by other sources."""

    manifest = KevConnector.manifest.model_copy(update={"id": "mapping", "snapshot": "map.bin"})

    def translate(self, raw: bytes) -> Translation:
        return Translation(
            links=[
                LinkRecord(
                    "affects",
                    ("vulnerability", "CVE-2024-10441"),
                    ("product", "broadcom:vmware-esx"),
                ),
                LinkRecord(
                    "affects",
                    ("vulnerability", "CVE-1999-0001"),
                    ("product", "broadcom:vmware-esx"),
                ),
            ]
        )


def test_links_between_objects_of_other_sources_are_resolved(
    engine, ontology, kev_loaded, tmp_path
):
    (tmp_path / "map.bin").write_bytes(b"v1")

    result = run_connector(engine, ontology, _Mapping(), mode="snapshot", snapshot_dir=tmp_path)

    assert (result.links, result.skipped) == (1, 1)
    linked = rows(
        engine,
        "SELECT t.key FROM links l JOIN objects s ON s.id = l.source_object_id "
        "JOIN objects t ON t.id = l.target_object_id WHERE s.key = 'CVE-2024-10441' ORDER BY t.key",
    )
    assert [row["key"] for row in linked] == [
        "broadcom:vmware-esx",
        "synology:diskstation-manager-dsm",
    ]
