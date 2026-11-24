"""Load the ontology file and refuse any schema that is inconsistent or describes people."""

import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from estran.ontology.schema import BUILTIN_SORT_KEYS, IDENTIFIER, Ontology


class OntologyError(ValueError):
    """The ontology file itself is invalid."""


# Estran analyses events, infrastructure, organisations and territories, never individuals.
# A schema naming one of these words (English or French) is refused at load time.
FORBIDDEN_WORDS = frozenset(
    {
        "person", "persons", "people", "individual", "individuals",
        "email", "emails", "phone", "phones", "birth", "birthday",
        "surname", "firstname", "lastname", "passport", "ssn",
        "personne", "personnes", "individu", "individus", "courriel", "courriels",
        "telephone", "téléphone", "naissance", "prenom", "prénom", "patronyme",
    }
)  # fmt: skip

_WORD_SPLIT = re.compile(r"[^a-zà-ÿ]+")
_IDENTIFIER = re.compile(IDENTIFIER)


def load_ontology(path: Path) -> Ontology:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise OntologyError(f"cannot read ontology file {path}: {error}") from error
    return parse_ontology(data)


def parse_ontology(data: Any) -> Ontology:
    try:
        ontology = Ontology.model_validate(data)
    except ValidationError as error:
        raise OntologyError(f"invalid ontology: {error}") from error
    _check_consistency(ontology)
    _check_no_personal_data(ontology)
    return ontology


def _check_consistency(ontology: Ontology) -> None:
    for type_id, object_type in ontology.object_types.items():
        _check_identifier(type_id)
        if object_type.layer not in ontology.layers:
            raise OntologyError(f"object type '{type_id}' uses unknown layer '{object_type.layer}'")
        for property_id, prop in object_type.properties.items():
            _check_identifier(property_id)
            if property_id in BUILTIN_SORT_KEYS:
                raise OntologyError(f"'{type_id}.{property_id}' shadows a built-in column")
            if (prop.type == "enum") != bool(prop.values):
                raise OntologyError(
                    f"'{type_id}.{property_id}': 'values' is required for enum and only for enum"
                )
        for column in object_type.columns:
            if column not in object_type.properties:
                raise OntologyError(f"object type '{type_id}' lists unknown column '{column}'")
        sort_key = object_type.default_sort.by
        if sort_key not in BUILTIN_SORT_KEYS and sort_key not in object_type.properties:
            raise OntologyError(f"object type '{type_id}' sorts by unknown property '{sort_key}'")

    for link_id, link_type in ontology.link_types.items():
        _check_identifier(link_id)
        for end in (link_type.source, link_type.target):
            if end not in ontology.object_types:
                raise OntologyError(f"link type '{link_id}' refers to unknown object type '{end}'")


def _check_identifier(identifier: str) -> None:
    if not _IDENTIFIER.match(identifier):
        raise OntologyError(f"'{identifier}' is not a valid identifier (expected snake_case)")


def _check_no_personal_data(ontology: Ontology) -> None:
    names: list[str] = []
    for type_id, object_type in ontology.object_types.items():
        names += [type_id, object_type.label, object_type.plural]
        for property_id, prop in object_type.properties.items():
            names += [property_id, prop.label]
    for link_id, link_type in ontology.link_types.items():
        names += [link_id, link_type.label, link_type.inverse_label]

    for name in names:
        forbidden = FORBIDDEN_WORDS.intersection(_WORD_SPLIT.split(name.lower()))
        if forbidden:
            raise OntologyError(
                f"'{name}' describes personal data ({', '.join(sorted(forbidden))}): "
                "Estran does not model individuals"
            )
