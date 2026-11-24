"""Check a record produced by a connector against the ontology before it reaches the database."""

from datetime import date, datetime
from typing import Any
from urllib.parse import urlsplit

from estran.ontology.schema import Ontology, PropertyType


class RecordError(ValueError):
    """An object or link does not fit the ontology."""


def validate_object(ontology: Ontology, type_id: str, properties: dict[str, Any]) -> dict[str, Any]:
    """Return the properties normalized, or raise RecordError. Empty values are dropped."""
    object_type = ontology.object_types.get(type_id)
    if object_type is None:
        raise RecordError(f"unknown object type '{type_id}'")

    normalized: dict[str, Any] = {}
    for name, value in properties.items():
        prop = object_type.properties.get(name)
        if prop is None:
            raise RecordError(f"'{type_id}' has no property '{name}'")
        if value is None:
            continue
        try:
            clean = _normalize(prop, value)
        except ValueError as error:
            raise RecordError(f"'{type_id}.{name}': {error}") from error
        if clean in ("", []):
            continue
        normalized[name] = clean

    for name, prop in object_type.properties.items():
        if prop.required and name not in normalized:
            raise RecordError(f"'{type_id}' is missing required property '{name}'")
    return normalized


def validate_link(ontology: Ontology, type_id: str, source_type: str, target_type: str) -> None:
    link_type = ontology.link_types.get(type_id)
    if link_type is None:
        raise RecordError(f"unknown link type '{type_id}'")
    if (source_type, target_type) != (link_type.source, link_type.target):
        raise RecordError(
            f"link '{type_id}' goes from '{link_type.source}' to '{link_type.target}', "
            f"not from '{source_type}' to '{target_type}'"
        )


def _normalize(prop: PropertyType, value: Any) -> Any:
    match prop.type:
        case "text":
            return _text(value)
        case "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError("expected an integer")
            return value
        case "number":
            if isinstance(value, bool) or not isinstance(value, int | float):
                raise ValueError("expected a number")
            return value
        case "boolean":
            if not isinstance(value, bool):
                raise ValueError("expected true or false")
            return value
        case "date":
            return _date(value)
        case "datetime":
            return _datetime(value)
        case "url":
            return _url(value)
        case "enum":
            if value not in (prop.values or {}):
                raise ValueError(f"'{value}' is not one of the declared values")
            return value
        case "text_list":
            if not isinstance(value, list):
                raise ValueError("expected a list of texts")
            return [item for item in (_text(item) for item in value) if item]


def _text(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("expected a text")
    return value.strip()


def _date(value: Any) -> str:
    if isinstance(value, datetime):
        raise ValueError("expected a date without time")
    if isinstance(value, date):
        return value.isoformat()
    text = _text(value)
    if not text:
        return ""
    if len(text) != 10:
        raise ValueError("expected a date as YYYY-MM-DD")
    try:
        return date.fromisoformat(text).isoformat()
    except ValueError:
        raise ValueError("expected a date as YYYY-MM-DD") from None


def _datetime(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    text = _text(value)
    if not text:
        return ""
    try:
        return datetime.fromisoformat(text).isoformat()
    except ValueError:
        raise ValueError("expected an ISO 8601 date and time") from None


def _url(value: Any) -> str:
    text = _text(value)
    if not text:
        return ""
    parts = urlsplit(text)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError("expected an http(s) URL")
    return text
