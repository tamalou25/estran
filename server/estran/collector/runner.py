"""Run one connector end to end: fetch, translate, validate against the ontology, load.

Every run leaves a row in `runs`, whatever happens. Data and the "success" status are written
in the same transaction, so a failed run never leaves half-loaded data.
"""

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from sqlalchemy import Engine, func, select, update
from sqlalchemy.dialects.postgresql import Insert, insert

from estran.collector.http import HttpClient, HttpError
from estran.collector.loader import load
from estran.collector.sdk import Connector, ConnectorError, LinkRecord, Manifest, ObjectRecord
from estran.db.tables import runs, sources
from estran.ontology import Ontology, RecordError, validate_link, validate_object

logger = logging.getLogger(__name__)

Mode = Literal["live", "snapshot"]
MAX_ERROR_LENGTH = 500


@dataclass(frozen=True, slots=True)
class RunResult:
    run_id: int
    status: Literal["success", "unchanged", "failed"]
    objects: int = 0
    links: int = 0
    skipped: int = 0
    error: str | None = None


@dataclass(frozen=True, slots=True)
class _Previous:
    """What the last good run of this source saw, to avoid reloading identical content."""

    etag: str | None
    content_sha256: str | None


@dataclass(frozen=True, slots=True)
class _Document:
    raw: bytes | None  # None: the source says nothing changed
    mode: Mode
    etag: str | None
    note: str | None = None


def run_connector(
    engine: Engine,
    ontology: Ontology,
    connector: Connector,
    *,
    mode: Mode,
    snapshot_dir: Path,
    client: HttpClient | None = None,
) -> RunResult:
    manifest = connector.manifest
    with engine.begin() as connection:
        connection.execute(_upsert_source(manifest))
        previous_row = connection.execute(
            select(runs.c.etag, runs.c.content_sha256)
            .where(runs.c.source_id == manifest.id, runs.c.status.in_(["success", "unchanged"]))
            .order_by(runs.c.id.desc())
            .limit(1)
        ).first()
        previous = _Previous(*previous_row) if previous_row else None
        run_id: int = connection.execute(
            insert(runs)
            .values(
                source_id=manifest.id,
                connector_version=manifest.version,
                mode=mode,
                status="running",
            )
            .returning(runs.c.id)
        ).scalar_one()

    try:
        return _run(engine, ontology, connector, run_id, mode, snapshot_dir, client, previous)
    except (HttpError, ConnectorError, OSError) as error:
        return _fail(engine, run_id, manifest, str(error))
    except Exception as error:
        _fail(engine, run_id, manifest, f"internal error: {error}")
        raise


def _run(
    engine: Engine,
    ontology: Ontology,
    connector: Connector,
    run_id: int,
    mode: Mode,
    snapshot_dir: Path,
    client: HttpClient | None,
    previous: _Previous | None,
) -> RunResult:
    manifest = connector.manifest
    document = _obtain(connector, mode, snapshot_dir, client, previous)
    sha256 = hashlib.sha256(document.raw).hexdigest() if document.raw is not None else None
    finished = {
        "mode": document.mode,
        "finished_at": func.now(),
        "etag": document.etag or (previous.etag if previous else None),
        "error": document.note,
    }

    if document.raw is None or (previous and sha256 == previous.content_sha256):
        with engine.begin() as connection:
            connection.execute(
                update(runs)
                .where(runs.c.id == run_id)
                .values(
                    status="unchanged",
                    content_sha256=sha256 or (previous.content_sha256 if previous else None),
                    **finished,
                )
            )
        logger.info("%s: unchanged since the last run", manifest.id)
        return RunResult(run_id, "unchanged")

    translation = connector.translate(document.raw)
    valid_objects, invalid_objects = _valid_objects(ontology, translation.objects)
    valid_links, invalid_links = _valid_links(ontology, translation.links)

    with engine.begin() as connection:
        counts = load(
            connection,
            ontology,
            run_id=run_id,
            source_id=manifest.id,
            object_records=valid_objects,
            link_records=valid_links,
        )
        skipped = translation.skipped + invalid_objects + invalid_links + counts.unresolved_links
        connection.execute(
            update(runs)
            .where(runs.c.id == run_id)
            .values(
                status="success",
                objects_count=counts.objects,
                links_count=counts.links,
                skipped_count=skipped,
                content_sha256=sha256,
                **finished,
            )
        )
    logger.info(
        "%s: %d objects, %d links, %d skipped (%s)",
        manifest.id,
        counts.objects,
        counts.links,
        skipped,
        document.mode,
    )
    return RunResult(run_id, "success", counts.objects, counts.links, skipped, document.note)


def _obtain(
    connector: Connector,
    mode: Mode,
    snapshot_dir: Path,
    client: HttpClient | None,
    previous: _Previous | None,
) -> _Document:
    manifest = connector.manifest
    if mode == "snapshot":
        return _Document(_read_snapshot(manifest, snapshot_dir), "snapshot", None)

    own_client = client is None
    http = client or HttpClient(manifest.domains)
    try:
        result = connector.fetch(http, previous.etag if previous else None)
    except HttpError as error:
        # Very first collection and the source is unreachable: start from the bundled
        # snapshot so the platform is usable offline. Later failures are just failures.
        if previous is None and manifest.snapshot:
            note = f"live fetch failed ({error}); bundled snapshot loaded instead"
            logger.warning("%s: %s", manifest.id, note)
            return _Document(_read_snapshot(manifest, snapshot_dir), "snapshot", None, note)
        raise
    finally:
        if own_client:
            http.close()
    return _Document(result.content, "live", result.etag)


def _read_snapshot(manifest: Manifest, snapshot_dir: Path) -> bytes:
    if not manifest.snapshot:
        raise ConnectorError(f"{manifest.id} has no snapshot (source not redistributable)")
    return (snapshot_dir / manifest.snapshot).read_bytes()


def _valid_objects(
    ontology: Ontology, records: list[ObjectRecord]
) -> tuple[list[ObjectRecord], int]:
    valid: list[ObjectRecord] = []
    for record in records:
        try:
            properties = validate_object(ontology, record.type, record.properties)
        except RecordError as error:
            logger.warning("object %s/%s refused: %s", record.type, record.key, error)
            continue
        if not record.key or not record.title:
            continue
        valid.append(ObjectRecord(record.type, record.key, record.title, properties))
    return valid, len(records) - len(valid)


def _valid_links(ontology: Ontology, records: list[LinkRecord]) -> tuple[list[LinkRecord], int]:
    valid: list[LinkRecord] = []
    for record in records:
        try:
            validate_link(ontology, record.type, record.source[0], record.target[0])
        except RecordError as error:
            logger.warning("link %s refused: %s", record.type, error)
            continue
        valid.append(record)
    return valid, len(records) - len(valid)


def _upsert_source(manifest: Manifest) -> Insert:
    values = {
        "name": manifest.name,
        "url": manifest.url,
        "homepage": manifest.homepage,
        "licence": manifest.licence,
        "licence_url": manifest.licence_url,
        "attribution": manifest.attribution,
        "redistributable": manifest.redistributable,
    }
    return (
        insert(sources)
        .values(id=manifest.id, **values)
        .on_conflict_do_update(
            index_elements=[sources.c.id], set_={**values, "updated_at": func.now()}
        )
    )


def _fail(engine: Engine, run_id: int, manifest: Manifest, message: str) -> RunResult:
    error = message[:MAX_ERROR_LENGTH]
    with engine.begin() as connection:
        connection.execute(
            update(runs)
            .where(runs.c.id == run_id)
            .values(status="failed", finished_at=func.now(), error=error)
        )
    logger.error("%s: run failed: %s", manifest.id, error)
    return RunResult(run_id, "failed", error=error)
