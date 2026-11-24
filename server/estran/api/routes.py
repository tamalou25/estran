"""The endpoints. All are GET: the API never writes."""

from collections.abc import Iterator
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import Connection, text

from estran.api import queries, schemas
from estran.ontology import BUILTIN_SORT_KEYS, ObjectType, Ontology

router = APIRouter(prefix="/api")

MAX_PAGE_SIZE = 200
MAX_FILTERS = 10


def get_ontology(request: Request) -> Ontology:
    ontology: Ontology = request.app.state.ontology
    return ontology


def get_connection(request: Request) -> Iterator[Connection]:
    with request.app.state.engine.connect() as connection:
        yield connection


OntologyDep = Annotated[Ontology, Depends(get_ontology)]
ConnectionDep = Annotated[Connection, Depends(get_connection)]


def _object_type(ontology: Ontology, type_id: str) -> ObjectType:
    object_type = ontology.object_types.get(type_id)
    if object_type is None:
        raise HTTPException(404, f"unknown object type '{type_id}'")
    return object_type


def _invalid(message: str) -> HTTPException:
    return HTTPException(422, message)


@router.get("/health")
def health(connection: ConnectionDep) -> schemas.Health:
    connection.execute(text("SELECT 1"))
    return schemas.Health(status="ok")


@router.get("/ontology")
def ontology(ontology: OntologyDep) -> dict[str, Any]:
    return ontology.model_dump(by_alias=True)


@router.get("/stats")
def stats(connection: ConnectionDep) -> schemas.Stats:
    objects, links = queries.get_stats(connection)
    return schemas.Stats(objects=objects, links=links)


@router.get("/objects")
def list_objects(
    ontology: OntologyDep,
    connection: ConnectionDep,
    type_id: Annotated[str, Query(alias="type", max_length=64)],
    q: Annotated[str, Query(max_length=200)] = "",
    filters: Annotated[list[str] | None, Query(alias="filter", max_length=MAX_FILTERS)] = None,
    sort: Annotated[str | None, Query(max_length=64)] = None,
    order: Literal["asc", "desc"] | None = None,
    page: Annotated[int, Query(ge=1, le=100_000)] = 1,
    size: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
) -> schemas.ObjectPage:
    object_type = _object_type(ontology, type_id)

    sort_key = sort or object_type.default_sort.by
    if sort_key not in BUILTIN_SORT_KEYS and sort_key not in object_type.properties:
        raise _invalid(f"'{type_id}' cannot be sorted by '{sort_key}'")
    descending = (order or object_type.default_sort.order) == "desc"

    parsed_filters: list[tuple[str, str]] = []
    for item in filters or []:
        name, separator, value = item.partition(":")
        if not separator or name not in object_type.properties:
            raise _invalid(f"filter '{item}' must be '<property>:<value>' on a declared property")
        parsed_filters.append((name, value))

    rows, total = queries.list_objects(
        connection,
        object_type,
        type_id=type_id,
        q=q.strip(),
        filters=parsed_filters,
        sort=sort_key,
        descending=descending,
        page=page,
        size=size,
    )
    return schemas.ObjectPage(
        items=[schemas.ObjectSummary.model_validate(dict(row)) for row in rows],
        total=total,
        page=page,
        size=size,
    )


@router.get("/objects/{type_id}/{key}")
def get_object(
    type_id: str, key: str, ontology: OntologyDep, connection: ConnectionDep
) -> schemas.ObjectDetail:
    row = _existing_object(ontology, connection, type_id, key)
    provenance = [
        schemas.Provenance(
            source=schemas.SourceInfo.model_validate(dict(p)),
            fields=p["fields"],
            first_seen=p["first_seen"],
            last_seen=p["last_seen"],
        )
        for p in queries.get_provenance(connection, row["id"])
    ]
    return schemas.ObjectDetail(
        **{k: v for k, v in row.items() if k != "id"}, provenance=provenance
    )


@router.get("/objects/{type_id}/{key}/neighbors")
def get_neighbors(
    type_id: str,
    key: str,
    ontology: OntologyDep,
    connection: ConnectionDep,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 100,
    offset: Annotated[int, Query(ge=0, le=10_000_000)] = 0,
) -> schemas.Neighbors:
    row = _existing_object(ontology, connection, type_id, key)
    rows, total = queries.get_neighbors(connection, row["id"], limit=limit, offset=offset)
    return schemas.Neighbors(
        items=[
            schemas.Neighbor(
                link_type=n["link_type"],
                direction=n["direction"],
                nature=n["nature"],
                object=schemas.ObjectRef(type=n["type"], key=n["key"], title=n["title"]),
            )
            for n in rows
        ],
        total=total,
    )


@router.get("/sources")
def list_sources(connection: ConnectionDep) -> list[schemas.SourceStatus]:
    sources = queries.list_sources(connection)
    run_ids = [s["last_run_id"] for s in sources if s["last_run_id"] is not None]
    runs = {r["id"]: r for r in queries.list_runs(connection, limit=len(run_ids), run_ids=run_ids)}
    return [
        schemas.SourceStatus(
            **{k: v for k, v in source.items() if k != "last_run_id"},
            last_run=schemas.Run.model_validate(dict(runs[source["last_run_id"]]))
            if source["last_run_id"] in runs
            else None,
        )
        for source in sources
    ]


@router.get("/runs")
def list_runs(
    connection: ConnectionDep, limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50
) -> list[schemas.Run]:
    return [schemas.Run.model_validate(dict(r)) for r in queries.list_runs(connection, limit=limit)]


def _existing_object(
    ontology: Ontology, connection: Connection, type_id: str, key: str
) -> dict[str, Any]:
    _object_type(ontology, type_id)
    row = queries.get_object(connection, type_id, key)
    if row is None:
        raise HTTPException(404, f"no {type_id} with key '{key}'")
    return dict(row)
