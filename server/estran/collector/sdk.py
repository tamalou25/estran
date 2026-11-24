"""What a connector is: a manifest saying where data comes from, and a pure translation.

Writing a connector means subclassing `Connector`, adding a `manifest.yaml` next to it and
implementing `translate`. Translation never touches the network or the database, so it is
tested on a recorded sample.
"""

import inspect
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from estran.collector.http import FetchResult, HttpClient

ObjectRef = tuple[str, str]  # (object type, key)


class ConnectorError(Exception):
    """The source returned something the connector cannot use at all."""


class Manifest(BaseModel):
    """Identity card of a source: where it lives, how often to ask, what its licence allows."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[a-z][a-z0-9-]*$")
    name: str
    version: str
    url: str
    homepage: str
    domains: list[str] = Field(min_length=1)
    licence: str
    licence_url: str
    attribution: str
    redistributable: bool
    schedule_hours: int = Field(ge=1)
    snapshot: str | None = None  # file name in the snapshot directory; redistributable only
    max_megabytes: int = Field(default=50, ge=1, le=500)  # largest document accepted
    # Sources this one builds on: it is run again, in full, whenever one of them changes.
    after: list[str] = Field(default_factory=list)
    # Object types this source adds fields to without ever creating them.
    enriches: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _snapshot_needs_a_redistributable_source(self) -> Self:
        if self.snapshot and not self.redistributable:
            raise ValueError("a non-redistributable source cannot ship a snapshot")
        return self


@dataclass(frozen=True, slots=True)
class ObjectRecord:
    type: str
    key: str
    title: str
    properties: dict[str, Any]


@dataclass(frozen=True, slots=True)
class LinkRecord:
    type: str
    source: ObjectRef
    target: ObjectRef
    properties: dict[str, Any] = field(default_factory=dict)
    nature: Literal["fact", "hypothesis"] = "fact"


@dataclass(frozen=True, slots=True)
class EnrichmentRecord:
    """Fields added to an object that another source created. Ignored if it does not exist."""

    type: str
    key: str
    properties: dict[str, Any]


@dataclass(slots=True)
class Translation:
    objects: list[ObjectRecord] = field(default_factory=list)
    links: list[LinkRecord] = field(default_factory=list)
    # May be a generator: a source scoring every CVE in the world yields hundreds of
    # thousands of records, of which only those matching known objects are kept.
    enrichments: Iterable[EnrichmentRecord] = ()
    skipped: int = 0


class Connector(ABC):
    manifest: ClassVar[Manifest]

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if inspect.isabstract(cls) or "manifest" in cls.__dict__:
            return
        path = Path(inspect.getfile(cls)).parent / "manifest.yaml"
        cls.manifest = Manifest.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))

    def is_configured(self) -> bool:
        """False for an optional source whose credential is missing: it is then left alone."""
        return True

    def fetch(self, client: HttpClient, etag: str | None) -> FetchResult:
        """Download the raw document. Override for sources needing more than one GET."""
        return client.get(self.manifest.url, etag=etag)

    @abstractmethod
    def translate(self, raw: bytes) -> Translation:
        """Turn the raw document into ontology records. Pure: no network, no database."""
