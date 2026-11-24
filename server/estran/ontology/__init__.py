"""Ontology engine: the schema of Estran's world and the checks that guard it."""

from estran.ontology.loader import OntologyError, load_ontology, parse_ontology
from estran.ontology.schema import (
    BUILTIN_SORT_KEYS,
    LinkType,
    ObjectType,
    Ontology,
    PropertyType,
)
from estran.ontology.validator import (
    RecordError,
    validate_link,
    validate_object,
    validate_properties,
)

__all__ = [
    "BUILTIN_SORT_KEYS",
    "LinkType",
    "ObjectType",
    "Ontology",
    "OntologyError",
    "PropertyType",
    "RecordError",
    "load_ontology",
    "parse_ontology",
    "validate_link",
    "validate_object",
    "validate_properties",
]
