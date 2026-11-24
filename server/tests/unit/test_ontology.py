import copy
from typing import Any

import pytest

from estran.ontology import (
    OntologyError,
    RecordError,
    load_ontology,
    parse_ontology,
    validate_link,
    validate_object,
)

MINIMAL: dict[str, Any] = {
    "version": 1,
    "layers": {"menace": {"label": "Menace"}},
    "object_types": {
        "vulnerability": {
            "label": "Vulnérabilité",
            "plural": "Vulnérabilités",
            "layer": "menace",
            "columns": ["added"],
            "default_sort": {"by": "added", "order": "desc"},
            "properties": {
                "name": {"label": "Nom", "type": "text", "required": True},
                "added": {"label": "Ajout", "type": "date"},
                "ransomware": {
                    "label": "Rançongiciel",
                    "type": "enum",
                    "values": {"known": "Avéré", "unknown": "Non connu"},
                },
                "cwes": {"label": "Faiblesses", "type": "text_list"},
                "score": {"label": "Score", "type": "number"},
                "link": {"label": "Lien", "type": "url"},
            },
        },
        "product": {
            "label": "Produit",
            "plural": "Produits",
            "layer": "menace",
            "properties": {"name": {"label": "Nom", "type": "text"}},
        },
    },
    "link_types": {
        "affects": {
            "label": "affecte",
            "inverse_label": "est affecté par",
            "from": "vulnerability",
            "to": "product",
        }
    },
}


def minimal(**changes: Any) -> dict[str, Any]:
    data = copy.deepcopy(MINIMAL)
    data.update(changes)
    return data


# --- loading the schema -------------------------------------------------------------------


def test_project_ontology_loads_with_the_phase_0a_types(ontology_path):
    ontology = load_ontology(ontology_path)

    assert {"vulnerability", "product", "vendor"} <= set(ontology.object_types)
    assert {"affects", "made_by"} <= set(ontology.link_types)
    assert ontology.link_types["affects"].source == "vulnerability"
    assert ontology.link_types["affects"].target == "product"


def test_unit_is_only_allowed_on_numbers():
    data = minimal()
    data["object_types"]["product"]["properties"]["name"]["unit"] = "percent"

    with pytest.raises(OntologyError, match="unit"):
        parse_ontology(data)


def test_link_type_pointing_to_an_unknown_object_type_is_rejected():
    data = minimal()
    data["link_types"]["affects"]["to"] = "router"

    with pytest.raises(OntologyError, match="router"):
        parse_ontology(data)


def test_object_type_in_an_unknown_layer_is_rejected():
    data = minimal()
    data["object_types"]["product"]["layer"] = "espace"

    with pytest.raises(OntologyError, match="espace"):
        parse_ontology(data)


def test_unknown_property_type_is_rejected():
    data = minimal()
    data["object_types"]["product"]["properties"]["name"]["type"] = "blob"

    with pytest.raises(OntologyError):
        parse_ontology(data)


def test_column_naming_an_unknown_property_is_rejected():
    data = minimal()
    data["object_types"]["vulnerability"]["columns"] = ["severity"]

    with pytest.raises(OntologyError, match="severity"):
        parse_ontology(data)


def test_default_sort_on_an_unknown_property_is_rejected():
    data = minimal()
    data["object_types"]["vulnerability"]["default_sort"] = {"by": "severity", "order": "asc"}

    with pytest.raises(OntologyError, match="severity"):
        parse_ontology(data)


def test_enum_property_without_values_is_rejected():
    data = minimal()
    del data["object_types"]["vulnerability"]["properties"]["ransomware"]["values"]

    with pytest.raises(OntologyError, match="ransomware"):
        parse_ontology(data)


# --- ethical guard: no personal data in the schema ----------------------------------------


@pytest.mark.parametrize("type_id", ["person", "private_individual", "people"])
def test_object_type_describing_a_person_is_rejected(type_id):
    data = minimal()
    data["object_types"][type_id] = data["object_types"].pop("product")
    data["link_types"]["affects"]["to"] = type_id

    with pytest.raises(OntologyError, match="personal data"):
        parse_ontology(data)


@pytest.mark.parametrize("property_id", ["email", "contact_email", "phone", "birth_date"])
def test_property_holding_personal_data_is_rejected(property_id):
    data = minimal()
    data["object_types"]["product"]["properties"][property_id] = {"label": "X", "type": "text"}

    with pytest.raises(OntologyError, match="personal data"):
        parse_ontology(data)


def test_french_label_describing_a_person_is_rejected():
    data = minimal()
    data["object_types"]["product"]["label"] = "Personne"

    with pytest.raises(OntologyError, match="personal data"):
        parse_ontology(data)


def test_word_merely_containing_a_forbidden_term_is_accepted():
    data = minimal()
    data["object_types"]["product"]["properties"]["personalization"] = {
        "label": "Personnalisation",
        "type": "text",
    }

    parse_ontology(data)


# --- validating records against the schema ------------------------------------------------


def test_valid_object_is_returned_normalized():
    ontology = parse_ontology(minimal())

    properties = validate_object(
        ontology,
        "vulnerability",
        {
            "name": "  Buffer overflow ",
            "added": "2024-05-01",
            "ransomware": "known",
            "cwes": ["CWE-79", "CWE-89"],
            "score": 7,
            "link": "https://www.cve.org/CVERecord?id=CVE-2024-0001",
        },
    )

    assert properties == {
        "name": "Buffer overflow",
        "added": "2024-05-01",
        "ransomware": "known",
        "cwes": ["CWE-79", "CWE-89"],
        "score": 7,
        "link": "https://www.cve.org/CVERecord?id=CVE-2024-0001",
    }


def test_empty_optional_values_are_dropped():
    ontology = parse_ontology(minimal())

    properties = validate_object(
        ontology, "vulnerability", {"name": "x", "added": None, "cwes": [], "link": ""}
    )

    assert properties == {"name": "x"}


def test_object_of_unknown_type_is_rejected():
    ontology = parse_ontology(minimal())

    with pytest.raises(RecordError, match="router"):
        validate_object(ontology, "router", {"name": "x"})


def test_object_with_undeclared_property_is_rejected():
    ontology = parse_ontology(minimal())

    with pytest.raises(RecordError, match="owner"):
        validate_object(ontology, "vulnerability", {"name": "x", "owner": "y"})


def test_object_missing_a_required_property_is_rejected():
    ontology = parse_ontology(minimal())

    with pytest.raises(RecordError, match="name"):
        validate_object(ontology, "vulnerability", {"added": "2024-05-01"})


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("added", "01/05/2024"),
        ("added", "2024-13-45"),
        ("ransomware", "maybe"),
        ("cwes", "CWE-79"),
        ("cwes", ["CWE-79", 3]),
        ("score", "high"),
        ("score", True),
        ("link", "javascript:alert(1)"),
        ("link", "ftp://example.org/file"),
        ("name", 42),
    ],
)
def test_property_value_of_the_wrong_kind_is_rejected(name, value):
    ontology = parse_ontology(minimal())

    with pytest.raises(RecordError, match=name):
        validate_object(ontology, "vulnerability", {"name": "x", name: value})


def test_link_between_the_declared_types_is_accepted():
    ontology = parse_ontology(minimal())

    validate_link(ontology, "affects", "vulnerability", "product")


def test_link_of_unknown_type_is_rejected():
    ontology = parse_ontology(minimal())

    with pytest.raises(RecordError, match="owns"):
        validate_link(ontology, "owns", "vulnerability", "product")


def test_link_between_the_wrong_types_is_rejected():
    ontology = parse_ontology(minimal())

    with pytest.raises(RecordError, match="affects"):
        validate_link(ontology, "affects", "product", "vulnerability")
