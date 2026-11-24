"""The shape of the ontology file: object types, their properties, and link types."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

PropertyKind = Literal[
    "text", "integer", "number", "boolean", "date", "datetime", "url", "enum", "text_list"
]

IDENTIFIER = r"^[a-z][a-z0-9_]*$"

# Columns every object has, usable for sorting next to the type's own properties.
BUILTIN_SORT_KEYS = ("title", "key", "first_seen", "last_seen")


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class PropertyType(_Model):
    label: str
    type: PropertyKind
    required: bool = False
    searchable: bool = False
    values: dict[str, str] | None = None  # enum only: stored value -> displayed label
    unit: Literal["percent"] | None = None  # number only: 0.25 is shown as 25 %


class SortSpec(_Model):
    by: str = "title"
    order: Literal["asc", "desc"] = "asc"


class Layer(_Model):
    label: str


class ObjectType(_Model):
    label: str
    plural: str
    layer: str
    description: str = ""
    columns: list[str] = Field(default_factory=list)
    default_sort: SortSpec = Field(default_factory=SortSpec)
    properties: dict[str, PropertyType]


class LinkWeight(_Model):
    """A number carried by the link itself, shown next to it ("12 indicateurs récents")."""

    property: str
    label: str


class LinkType(_Model):
    label: str
    inverse_label: str
    weight: LinkWeight | None = None
    source: str = Field(alias="from")
    target: str = Field(alias="to")


class Ontology(_Model):
    version: int
    layers: dict[str, Layer]
    object_types: dict[str, ObjectType]
    link_types: dict[str, LinkType] = Field(default_factory=dict)
