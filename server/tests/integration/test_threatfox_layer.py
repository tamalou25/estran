"""ThreatFox end to end: from the API answer to the store, without a single address kept."""

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from support import served
from unit.test_threatfox import ANSWER, TABLE

from estran.api.main import create_app
from estran.collector.connectors.threatfox import ThreatFoxConnector
from estran.collector.connectors.threatfox.connector import KEY_FILE_ENV
from estran.collector.http import HttpClient
from estran.collector.runner import run_connector


@pytest.fixture
def api(engine, ontology, tmp_path, monkeypatch) -> TestClient:
    key = tmp_path / "abusech_auth_key"
    key.write_text("integration-test-key", encoding="utf-8")
    monkeypatch.setenv(KEY_FILE_ENV, str(key))

    def handler(request: httpx.Request) -> httpx.Response:
        return served(ANSWER if request.url.host == "threatfox-api.abuse.ch" else TABLE)

    connector = ThreatFoxConnector()
    client = HttpClient(connector.manifest.domains, transport=httpx.MockTransport(handler))
    result = run_connector(
        engine, ontology, connector, mode="live", snapshot_dir=tmp_path, client=client
    )
    assert result.status == "success"
    return TestClient(create_app(engine=engine, ontology=ontology))


def test_family_leads_to_the_networks_hosting_it_with_a_count(api):
    body = api.get("/api/objects/malware_family/win.dridex/neighbors").json()

    hosted = {n["object"]["key"]: n["properties"] for n in body["items"]}
    assert hosted["AS13335"]["indicator_count"] == 2
    assert hosted["AS3215"]["indicator_count"] == 1
    assert {n["link_type"] for n in body["items"]} == {"family_hosted_in"}


def test_network_leads_to_its_country_and_back_to_the_families(api):
    body = api.get("/api/objects/autonomous_system/AS3215/neighbors").json()

    found = {(n["link_type"], n["direction"], n["object"]["key"]) for n in body["items"]}
    assert found == {
        ("as_registered_in", "out", "FR"),
        ("family_hosted_in", "in", "win.dridex"),
        ("family_hosted_in", "in", "win.qakbot"),
    }
    assert api.get("/api/objects/country/FR").json()["title"] == "France"


def test_the_three_layers_now_hold_objects(api):
    counts = api.get("/api/stats").json()["objects"]

    assert counts == {"malware_family": 2, "autonomous_system": 2, "country": 2}


def test_no_address_reporter_or_key_is_stored_anywhere(api, engine):
    secrets = ("1.0.0.7", "2.4.6.8", "evil-panel", "jeanne_dupont", "integration-test-key")
    with engine.connect() as connection:
        dump = " ".join(
            str(row)
            for table in ("objects", "links", "provenance", "runs", "sources")
            for row in connection.execute(text(f"SELECT * FROM {table}"))
        )

    for secret in secrets:
        assert secret not in dump


def test_source_is_shown_as_not_redistributable(api):
    [source] = api.get("/api/sources").json()

    assert source["id"] == "abusech-threatfox"
    assert source["redistributable"] is False
    assert "non lucratif" in source["licence"]
