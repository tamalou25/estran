"""Write validated records into the database. Idempotent: loading twice changes nothing.

Objects are upserted on (type, key) and links on (type, source, target). Properties from
several sources are merged, and `provenance` remembers which source provided which fields.
"""

from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection, bindparam, func, tuple_, update
from sqlalchemy.dialects.postgresql import JSONB, insert

from estran.collector.sdk import EnrichmentRecord, LinkRecord, ObjectRecord, ObjectRef
from estran.db.tables import links, objects, provenance
from estran.ontology import Ontology, RecordError, validate_properties

BATCH = 500


@dataclass(frozen=True, slots=True)
class LoadCounts:
    objects: int
    links: int
    unresolved_links: int


def load(
    connection: Connection,
    ontology: Ontology,
    *,
    run_id: int,
    source_id: str,
    object_records: Sequence[ObjectRecord],
    link_records: Sequence[LinkRecord],
) -> LoadCounts:
    """Expects records already validated against the ontology. Runs in the caller's transaction."""
    unique_objects = list({(r.type, r.key): r for r in object_records}.values())
    ids = _upsert_objects(connection, ontology, unique_objects)
    _record_provenance(
        connection,
        "object_id",
        [(ids[(r.type, r.key)], sorted(r.properties)) for r in unique_objects],
        run_id,
        source_id,
    )

    unique_links = list({(r.type, r.source, r.target): r for r in link_records}.values())
    ids.update(_find_existing(connection, _missing_refs(unique_links, ids)))
    resolved = [r for r in unique_links if r.source in ids and r.target in ids]
    link_ids = _upsert_links(connection, resolved, ids)
    _record_provenance(
        connection, "link_id", [(link_id, []) for link_id in link_ids], run_id, source_id
    )
    return LoadCounts(len(unique_objects), len(resolved), len(unique_links) - len(resolved))


def enrich(
    connection: Connection,
    ontology: Ontology,
    *,
    run_id: int,
    source_id: str,
    types: Sequence[str],
    records: Iterable[EnrichmentRecord],
) -> tuple[int, int]:
    """Add fields to objects that already exist. Returns (objects enriched, invalid records).

    A record about an object Estran does not hold is ignored: that is expected, not an error
    (a score exists for every CVE in the world, Estran keeps only the ones it knows).
    Enrichment fields are scores and dates; the searchable text is not recomputed.
    """
    if not types:
        return 0, sum(1 for _ in records)
    known = {
        (row.type, row.key): row.id
        for row in connection.execute(
            objects.select()
            .with_only_columns(objects.c.id, objects.c.type, objects.c.key)
            .where(objects.c.type.in_(list(types)))
        )
    }
    updates: dict[int, dict[str, Any]] = {}
    invalid = 0
    for record in records:
        object_id = known.get((record.type, record.key))
        if object_id is None:
            continue
        try:
            properties = validate_properties(ontology, record.type, record.properties)
        except RecordError:
            invalid += 1
            continue
        if properties:
            updates.setdefault(object_id, {}).update(properties)

    statement = (
        update(objects)
        .where(objects.c.id == bindparam("object_id"))
        .values(
            properties=objects.c.properties.op("||")(bindparam("added", type_=JSONB)),
            last_seen=func.now(),
        )
    )
    for batch in _batches(list(updates.items())):
        connection.execute(statement, [{"object_id": i, "added": added} for i, added in batch])
    _record_provenance(
        connection,
        "object_id",
        [(object_id, sorted(added)) for object_id, added in updates.items()],
        run_id,
        source_id,
    )
    return len(updates), invalid


def search_text(
    ontology: Ontology, type_id: str, key: str, title: str, props: dict[str, Any]
) -> str:
    """Lowercase text the search runs on: key, title and the properties declared searchable."""
    object_type = ontology.object_types[type_id]
    parts = [key, title]
    parts += [
        str(props[name])
        for name, prop in object_type.properties.items()
        if prop.searchable and name in props and props[name] != title
    ]
    return " ".join(parts).lower()


def _batches[T](rows: Sequence[T]) -> Iterator[Sequence[T]]:
    for start in range(0, len(rows), BATCH):
        yield rows[start : start + BATCH]


def _upsert_objects(
    connection: Connection, ontology: Ontology, records: Sequence[ObjectRecord]
) -> dict[ObjectRef, int]:
    ids: dict[ObjectRef, int] = {}
    stale: list[dict[str, Any]] = []
    for batch in _batches(records):
        statement = insert(objects).values(
            [
                {
                    "type": r.type,
                    "key": r.key,
                    "title": r.title,
                    "properties": r.properties,
                    "search_text": search_text(ontology, r.type, r.key, r.title, r.properties),
                }
                for r in batch
            ]
        )
        upsert = statement.on_conflict_do_update(
            constraint="uq_objects_type_key",
            set_={
                "title": statement.excluded.title,
                # merge: a source adds or refreshes its fields, it never erases another's
                "properties": objects.c.properties.op("||")(statement.excluded.properties),
                "last_seen": func.now(),
            },
        ).returning(
            objects.c.id,
            objects.c.type,
            objects.c.key,
            objects.c.title,
            objects.c.properties,
            objects.c.search_text,
        )
        for row in connection.execute(upsert):
            ids[(row.type, row.key)] = row.id
            # After a merge the searchable text must reflect the merged properties.
            text = search_text(ontology, row.type, row.key, row.title, row.properties)
            if text != row.search_text:
                stale.append({"object_id": row.id, "text": text})
    if stale:
        connection.execute(
            update(objects)
            .where(objects.c.id == bindparam("object_id"))
            .values(search_text=bindparam("text")),
            stale,
        )
    return ids


def _missing_refs(records: Sequence[LinkRecord], ids: dict[ObjectRef, int]) -> list[ObjectRef]:
    refs = {ref for r in records for ref in (r.source, r.target)}
    return sorted(refs - ids.keys())


def _find_existing(connection: Connection, refs: Sequence[ObjectRef]) -> dict[ObjectRef, int]:
    """Objects a link points to that were loaded earlier, possibly by another source."""
    found: dict[ObjectRef, int] = {}
    for batch in _batches(refs):
        query = objects.select().with_only_columns(objects.c.id, objects.c.type, objects.c.key)
        query = query.where(tuple_(objects.c.type, objects.c.key).in_(list(batch)))
        for row in connection.execute(query):
            found[(row.type, row.key)] = row.id
    return found


def _upsert_links(
    connection: Connection, records: Sequence[LinkRecord], ids: dict[ObjectRef, int]
) -> list[int]:
    link_ids: list[int] = []
    for batch in _batches(records):
        statement = insert(links).values(
            [
                {
                    "type": r.type,
                    "source_object_id": ids[r.source],
                    "target_object_id": ids[r.target],
                    "properties": r.properties,
                    "nature": r.nature,
                }
                for r in batch
            ]
        )
        upsert = statement.on_conflict_do_update(
            constraint="uq_links_type_source_target",
            set_={
                "properties": links.c.properties.op("||")(statement.excluded.properties),
                "nature": statement.excluded.nature,
                "last_seen": func.now(),
            },
        ).returning(links.c.id)
        link_ids += list(connection.execute(upsert).scalars())
    return link_ids


def _record_provenance(
    connection: Connection,
    subject: str,
    rows: Sequence[tuple[int, list[str]]],
    run_id: int,
    source_id: str,
) -> None:
    column = provenance.c[subject]
    for batch in _batches(rows):
        statement = insert(provenance).values(
            [
                {
                    subject: subject_id,
                    "source_id": source_id,
                    "first_run_id": run_id,
                    "last_run_id": run_id,
                    "fields": fields,
                }
                for subject_id, fields in batch
            ]
        )
        statement = statement.on_conflict_do_update(
            index_elements=[column, provenance.c.source_id],
            index_where=column.isnot(None),
            set_={
                "last_run_id": statement.excluded.last_run_id,
                "fields": statement.excluded.fields,
                "last_seen": func.now(),
            },
        )
        connection.execute(statement)
