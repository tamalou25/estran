import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect

from estran.api.main import create_app
from estran.collector.connectors.kev import KevConnector
from estran.collector.runner import run_connector


@pytest.fixture
def api(engine, ontology, snapshot_dir) -> TestClient:
    """The API over a database holding the 5-entry KEV sample."""
    run_connector(engine, ontology, KevConnector(), mode="snapshot", snapshot_dir=snapshot_dir)
    return TestClient(create_app(engine=engine, ontology=ontology))


def keys(response) -> list[str]:
    return [item["key"] for item in response.json()["items"]]


# --- service ------------------------------------------------------------------------------


def test_health_reports_a_reachable_database(api):
    response = api.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_ontology_is_served_as_the_interface_expects_it(api):
    body = api.get("/api/ontology").json()

    assert {"vulnerability", "product", "vendor"} <= set(body["object_types"])
    assert body["link_types"]["affects"]["from"] == "vulnerability"
    assert body["link_types"]["affects"]["to"] == "product"
    assert body["object_types"]["vulnerability"]["properties"]["ransomware_use"]["values"] == {
        "known": "Avéré",
        "unknown": "Non connu",
    }


def test_stats_count_objects_by_type(api):
    assert api.get("/api/stats").json() == {
        "objects": {"vulnerability": 5, "product": 4, "vendor": 3},
        "links": 9,
    }


def test_schema_is_published_but_no_page_loading_third_party_scripts(api):
    assert api.get("/api/openapi.json").status_code == 200
    assert api.get("/api/docs").status_code == 404
    assert api.get("/docs").status_code == 404


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_api_is_read_only(api, method):
    response = getattr(api, method)("/api/objects")

    assert response.status_code == 405


# --- listing ------------------------------------------------------------------------------


def test_objects_are_listed_in_the_default_order_of_their_type(api):
    response = api.get("/api/objects", params={"type": "vulnerability"})

    assert response.status_code == 200
    body = response.json()
    assert (body["total"], body["page"], body["size"]) == (5, 1, 50)
    # default_sort of vulnerability: kev_date_added, most recent first
    assert keys(response)[0] == "CVE-2026-123890"
    assert keys(response)[-1] == "CVE-2026-59310"
    assert body["items"][0]["properties"]["kev_date_added"] == "2026-11-20"


def test_objects_can_be_sorted_by_a_chosen_column(api):
    response = api.get(
        "/api/objects", params={"type": "vulnerability", "sort": "key", "order": "asc"}
    )

    assert keys(response) == sorted(keys(response))
    assert keys(response)[0] == "CVE-2024-10441"


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("synology", ["CVE-2024-10441"]),
        ("SYNOLOGY", ["CVE-2024-10441"]),
        ("cve-2026-41709", ["CVE-2026-41709"]),
        ("no-such-thing", []),
        ("%", []),
        ("_", []),
    ],
)
def test_search_matches_text_literally_and_ignores_case(api, query, expected):
    response = api.get("/api/objects", params={"type": "vulnerability", "q": query})

    assert response.status_code == 200
    assert keys(response) == expected


def test_objects_can_be_filtered_on_a_property_value(api):
    response = api.get(
        "/api/objects", params={"type": "vulnerability", "filter": "ransomware_use:known"}
    )

    assert sorted(keys(response)) == ["CVE-2024-10441", "CVE-2026-59310"]
    assert response.json()["total"] == 2


def test_results_are_paginated(api):
    response = api.get(
        "/api/objects",
        params={"type": "vulnerability", "sort": "key", "order": "asc", "size": 2, "page": 3},
    )

    body = response.json()
    assert (body["total"], body["page"], body["size"]) == (5, 3, 2)
    assert len(body["items"]) == 1


@pytest.mark.parametrize(
    "params",
    [
        {},
        {"type": "vulnerability", "size": 1000},
        {"type": "vulnerability", "page": 0},
        {"type": "vulnerability", "order": "sideways"},
        {"type": "vulnerability", "sort": "owner"},
        {"type": "vulnerability", "sort": "title; DROP TABLE objects"},
        {"type": "vulnerability", "filter": "owner:someone"},
        {"type": "vulnerability", "filter": "no-colon"},
        {"type": "vulnerability", "q": "x" * 201},
    ],
)
def test_invalid_listing_parameters_are_refused(api, engine, params):
    response = api.get("/api/objects", params=params)

    assert response.status_code == 422
    assert "objects" in inspect(engine).get_table_names()


def test_listing_an_unknown_type_is_not_found(api):
    assert api.get("/api/objects", params={"type": "spaceship"}).status_code == 404


# --- one object ---------------------------------------------------------------------------


def test_object_is_returned_with_its_provenance(api):
    response = api.get("/api/objects/vulnerability/CVE-2024-10441")

    assert response.status_code == 200
    body = response.json()
    assert body["type"] == "vulnerability"
    assert body["key"] == "CVE-2024-10441"
    assert body["properties"]["ransomware_use"] == "known"
    [provenance] = body["provenance"]
    assert provenance["source"]["id"] == "cisa-kev"
    assert provenance["source"]["licence"] == "CC0 1.0"
    assert provenance["source"]["homepage"].startswith("https://www.cisa.gov/")
    assert "kev_date_added" in provenance["fields"]
    assert provenance["last_seen"] >= provenance["first_seen"]


def test_object_key_may_contain_a_colon(api):
    response = api.get("/api/objects/product/broadcom:vmware-vcenter")

    assert response.status_code == 200
    assert response.json()["title"] == "VMware vCenter"


@pytest.mark.parametrize(
    "path",
    [
        "/api/objects/vulnerability/CVE-1999-0000",
        "/api/objects/spaceship/x",
        "/api/objects/vulnerability/CVE-1999-0000/neighbors",
    ],
)
def test_unknown_object_is_not_found(api, path):
    assert api.get(path).status_code == 404


def test_neighbors_follow_links_in_both_directions(api):
    response = api.get("/api/objects/product/broadcom:vmware-vcenter/neighbors")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 3
    found = {(n["link_type"], n["direction"], n["object"]["key"]) for n in body["items"]}
    assert found == {
        ("affects", "in", "CVE-2026-123890"),
        ("affects", "in", "CVE-2026-59310"),
        ("made_by", "out", "broadcom"),
    }
    assert {n["nature"] for n in body["items"]} == {"fact"}
    vendor = next(n["object"] for n in body["items"] if n["link_type"] == "made_by")
    assert vendor == {"type": "vendor", "key": "broadcom", "title": "Broadcom"}


def test_neighbors_can_be_limited_while_reporting_the_total(api):
    response = api.get(
        "/api/objects/product/broadcom:vmware-vcenter/neighbors", params={"limit": 1}
    )

    body = response.json()
    assert len(body["items"]) == 1
    assert body["total"] == 3


# --- sources ------------------------------------------------------------------------------


def test_sources_report_their_licence_and_last_run(api):
    [source] = api.get("/api/sources").json()

    assert source["id"] == "cisa-kev"
    assert source["licence"] == "CC0 1.0"
    assert source["redistributable"] is True
    assert source["objects_count"] == 12
    assert source["last_run"]["status"] == "success"
    assert source["last_run"]["mode"] == "snapshot"
    assert source["last_run"]["objects_count"] == 12


def test_runs_are_listed_most_recent_first(api, engine, ontology, snapshot_dir):
    run_connector(engine, ontology, KevConnector(), mode="snapshot", snapshot_dir=snapshot_dir)

    runs = api.get("/api/runs").json()

    assert [run["status"] for run in runs] == ["unchanged", "success"]
    assert runs[0]["id"] > runs[1]["id"]


def test_empty_database_answers_with_empty_results(engine, ontology):
    api = TestClient(create_app(engine=engine, ontology=ontology))

    assert api.get("/api/objects", params={"type": "vulnerability"}).json()["total"] == 0
    assert api.get("/api/sources").json() == []
    assert api.get("/api/stats").json() == {"objects": {}, "links": 0}
