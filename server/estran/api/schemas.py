"""Shapes of the API answers. web/src/api/types.ts mirrors this file."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel


class ObjectSummary(BaseModel):
    type: str
    key: str
    title: str
    properties: dict[str, Any]
    first_seen: datetime
    last_seen: datetime


class ObjectPage(BaseModel):
    items: list[ObjectSummary]
    total: int
    page: int
    size: int


class SourceInfo(BaseModel):
    id: str
    name: str
    homepage: str
    licence: str
    licence_url: str
    attribution: str
    redistributable: bool


class Provenance(BaseModel):
    source: SourceInfo
    fields: list[str]
    first_seen: datetime
    last_seen: datetime


class ObjectDetail(ObjectSummary):
    provenance: list[Provenance]


class ObjectRef(BaseModel):
    type: str
    key: str
    title: str


class Neighbor(BaseModel):
    link_type: str
    direction: Literal["out", "in"]
    nature: Literal["fact", "hypothesis"]
    properties: dict[str, Any]
    object: ObjectRef


class Neighbors(BaseModel):
    items: list[Neighbor]
    total: int


class Stats(BaseModel):
    objects: dict[str, int]
    links: int


class Run(BaseModel):
    id: int
    source_id: str
    mode: str
    status: Literal["running", "success", "unchanged", "failed"]
    started_at: datetime
    finished_at: datetime | None
    objects_count: int
    links_count: int
    skipped_count: int
    error: str | None


class SourceStatus(SourceInfo):
    objects_count: int
    last_run: Run | None


class Health(BaseModel):
    status: Literal["ok"]
