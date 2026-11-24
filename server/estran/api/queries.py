"""Every SQL query the API runs. Values are always bound parameters, never string-built.

The only pieces of SQL assembled dynamically are the ORDER BY expression and direction, and
both are picked from fixed strings after the request was checked against the ontology.
"""

from collections.abc import Sequence
from typing import Any

from sqlalchemy import Connection, RowMapping, text

from estran.ontology import BUILTIN_SORT_KEYS, ObjectType

_OBJECT_COLUMNS = "type, key, title, properties, first_seen, last_seen"
_SOURCE_COLUMNS = (
    "s.id, s.name, s.homepage, s.licence, s.licence_url, s.attribution, s.redistributable"
)
_RUN_COLUMNS = (
    "id, source_id, mode, status, started_at, finished_at, "
    "objects_count, links_count, skipped_count, error"
)
_NUMERIC_KINDS = ("integer", "number")


def escape_like(value: str) -> str:
    """Make user text literal inside a LIKE pattern ('%' and '_' lose their special meaning)."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def list_objects(
    connection: Connection,
    object_type: ObjectType,
    *,
    type_id: str,
    q: str,
    filters: Sequence[tuple[str, str]],
    sort: str,
    descending: bool,
    page: int,
    size: int,
) -> tuple[list[RowMapping], int]:
    """`sort` and the filter property names must already be validated against `object_type`."""
    where = ["type = :type"]
    params: dict[str, Any] = {"type": type_id}
    if q:
        where.append(r"search_text LIKE :pattern ESCAPE '\'")
        params["pattern"] = f"%{escape_like(q.lower())}%"
    for index, (name, value) in enumerate(filters):
        where.append(f"properties ->> :filter_name_{index} = :filter_value_{index}")
        params[f"filter_name_{index}"] = name
        params[f"filter_value_{index}"] = value
    condition = " AND ".join(where)

    if sort in BUILTIN_SORT_KEYS:
        order_by = sort
    else:
        params["sort_property"] = sort
        numeric = object_type.properties[sort].type in _NUMERIC_KINDS
        order_by = "(properties ->> :sort_property)" + ("::numeric" if numeric else "")
    direction = "DESC" if descending else "ASC"

    total: int = connection.execute(
        text(f"SELECT count(*) FROM objects WHERE {condition}"),
        params,
    ).scalar_one()
    rows = connection.execute(
        text(
            f"SELECT {_OBJECT_COLUMNS} FROM objects WHERE {condition} "
            f"ORDER BY {order_by} {direction} NULLS LAST, key ASC LIMIT :limit OFFSET :offset"
        ),
        {**params, "limit": size, "offset": (page - 1) * size},
    ).mappings()
    return list(rows), total


def get_object(connection: Connection, type_id: str, key: str) -> RowMapping | None:
    return (
        connection.execute(
            text(f"SELECT id, {_OBJECT_COLUMNS} FROM objects WHERE type = :type AND key = :key"),
            {"type": type_id, "key": key},
        )
        .mappings()
        .first()
    )


def get_provenance(connection: Connection, object_id: int) -> list[RowMapping]:
    return list(
        connection.execute(
            text(
                f"SELECT {_SOURCE_COLUMNS}, p.fields, p.first_seen, p.last_seen "
                "FROM provenance p JOIN sources s ON s.id = p.source_id "
                "WHERE p.object_id = :object_id ORDER BY s.name"
            ),
            {"object_id": object_id},
        ).mappings()
    )


_NEIGHBORS = """
    SELECT l.type AS link_type, 'out' AS direction, l.nature, o.type, o.key, o.title
    FROM links l JOIN objects o ON o.id = l.target_object_id
    WHERE l.source_object_id = :object_id
    UNION ALL
    SELECT l.type AS link_type, 'in' AS direction, l.nature, o.type, o.key, o.title
    FROM links l JOIN objects o ON o.id = l.source_object_id
    WHERE l.target_object_id = :object_id
"""


def get_neighbors(
    connection: Connection, object_id: int, *, limit: int, offset: int
) -> tuple[list[RowMapping], int]:
    params = {"object_id": object_id}
    total: int = connection.execute(
        text(f"SELECT count(*) FROM ({_NEIGHBORS}) AS neighbors"),
        params,
    ).scalar_one()
    # Balanced order: the first neighbour of every relation, then the second of each, and so
    # on. A short list (graph, capped page) then shows every kind of relation instead of
    # only the one that happens to sort first.
    rows = connection.execute(
        text(
            "SELECT link_type, direction, nature, type, key, title FROM ("
            "  SELECT neighbors.*, row_number() OVER ("
            "    PARTITION BY link_type, direction ORDER BY title, key"
            f"  ) AS position FROM ({_NEIGHBORS}) AS neighbors"
            ") AS ranked "
            "ORDER BY position, link_type, direction LIMIT :limit OFFSET :offset"
        ),
        {**params, "limit": limit, "offset": offset},
    ).mappings()
    return list(rows), total


def get_stats(connection: Connection) -> tuple[dict[str, int], int]:
    counts = connection.execute(text("SELECT type, count(*) FROM objects GROUP BY type"))
    links: int = connection.execute(text("SELECT count(*) FROM links")).scalar_one()
    return {row[0]: row[1] for row in counts}, links


def list_sources(connection: Connection) -> list[RowMapping]:
    return list(
        connection.execute(
            text(
                f"SELECT {_SOURCE_COLUMNS}, "
                "(SELECT count(*) FROM provenance p "
                " WHERE p.source_id = s.id AND p.object_id IS NOT NULL) AS objects_count, "
                "(SELECT max(r.id) FROM runs r WHERE r.source_id = s.id) AS last_run_id "
                "FROM sources s ORDER BY s.name"
            )
        ).mappings()
    )


def list_runs(
    connection: Connection, *, limit: int, run_ids: Sequence[int] | None = None
) -> list[RowMapping]:
    if run_ids is not None:
        query = text(f"SELECT {_RUN_COLUMNS} FROM runs WHERE id = ANY(:ids)")
        return list(connection.execute(query, {"ids": list(run_ids)}).mappings())
    query = text(f"SELECT {_RUN_COLUMNS} FROM runs ORDER BY id DESC LIMIT :limit")
    return list(connection.execute(query, {"limit": limit}).mappings())
