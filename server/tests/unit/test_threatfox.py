"""abuse.ch ThreatFox, aggregated by network: no indicator, address or reporter is ever kept."""

import gzip
import json

import httpx
import pytest
from support import served

from estran.collector.connectors.threatfox import ThreatFoxConnector
from estran.collector.connectors.threatfox.connector import KEY_FILE_ENV, AsnTable, reduce
from estran.collector.http import HttpClient, HttpError
from estran.collector.scheduler import runnable
from estran.collector.sdk import ConnectorError
from estran.ontology import load_ontology, validate_link, validate_object

TABLE = gzip.compress(
    b"1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET - Cloudflare, Inc.\n"
    b"1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n"
    b"2.3.0.0\t2.15.255.255\t3215\tFR\tAS3215 Orange S.A.\n"
    b"garbage line\n"
)


def ioc(
    value: str, kind: str = "ip:port", family: str = "win.dridex", name: str = "Dridex"
) -> dict:
    return {
        "id": "41",
        "ioc": value,
        "threat_type": "botnet_cc",
        "ioc_type": kind,
        "malware": family,
        "malware_printable": name,
        "malware_alias": "Bugat,Cridex",
        "malware_malpedia": f"https://malpedia.caad.fkie.fraunhofer.de/details/{family}",
        "confidence_level": 75,
        "first_seen": "2026-11-23 13:36:27 UTC",
        "reporter": "jeanne_dupont",
        "reference": "https://example.org/post/1",
        "tags": ["exe"],
    }


ANSWER = json.dumps(
    {
        "query_status": "ok",
        "data": [
            ioc("1.0.0.7:443"),
            ioc("1.0.0.9:8080"),
            ioc("2.4.6.8:447"),
            ioc("1.0.2.2:80"),  # not routed: counted for the family, located nowhere
            ioc("evil-panel.example", kind="domain"),
            ioc("2.4.6.9:443", family="win.qakbot", name="QakBot"),
            ioc("9.9.9.9:1", family="DROP TABLE objects", name="x"),
            "nonsense",
        ],
    }
).encode()


@pytest.fixture(scope="module")
def table() -> AsnTable:
    return AsnTable.parse(TABLE)


@pytest.fixture(scope="module")
def translation(table):
    return ThreatFoxConnector().translate(reduce(ANSWER, table))


# --- network table -----------------------------------------------------------------------------


def test_address_is_located_in_its_network(table):
    assert table.lookup("1.0.0.7") == (13335, "US", "CLOUDFLARENET - Cloudflare, Inc.")
    assert table.lookup("2.15.255.255") == (3215, "FR", "AS3215 Orange S.A.")


@pytest.mark.parametrize("address", ["1.0.2.2", "8.8.8.8", "0.0.0.1", "not an ip", "::1", ""])
def test_unrouted_unknown_or_invalid_address_has_no_network(table, address):
    assert table.lookup(address) is None


def test_file_that_is_not_the_expected_table_is_an_error():
    with pytest.raises(ConnectorError):
        AsnTable.parse(b"plain text")
    with pytest.raises(ConnectorError):
        AsnTable.parse(gzip.compress(b"only garbage\n"))


# --- reduction: what leaves the fetch step ---------------------------------------------------------


def test_reduced_document_holds_no_indicator_address_or_reporter(table):
    reduced = reduce(ANSWER, table).decode()

    for secret in ("1.0.0.7", "2.4.6.8", "evil-panel", "jeanne_dupont", "example.org/post"):
        assert secret not in reduced
    assert "win.dridex" in reduced and "13335" in reduced


@pytest.mark.parametrize("status", ["unknown_auth_key", "illegal_days", "no_result"])
def test_refused_query_is_an_error_naming_the_reason(table, status):
    with pytest.raises(ConnectorError, match=status):
        reduce(json.dumps({"query_status": status, "data": "..."}).encode(), table)


def test_answer_that_is_not_json_is_an_error(table):
    with pytest.raises(ConnectorError):
        reduce(b"<html>", table)


# --- translation -----------------------------------------------------------------------------------


def test_families_networks_and_countries_become_objects(translation):
    objects = {(o.type, o.key): o for o in translation.objects}

    family = objects[("malware_family", "win.dridex")]
    assert family.title == "Dridex"
    assert family.properties["aliases"] == ["Bugat", "Cridex"]
    assert family.properties["url"].endswith("/details/win.dridex")
    network = objects[("autonomous_system", "AS13335")]
    assert network.title == "CLOUDFLARENET - Cloudflare, Inc."
    assert network.properties["number"] == 13335
    assert objects[("country", "FR")].title == "France"
    assert objects[("country", "US")].title == "États-Unis"
    assert ("malware_family", "win.qakbot") in objects
    assert not any("DROP" in key for _, key in objects)


def test_links_count_recent_indicators_per_family_and_network(translation):
    hosted = {
        (link.source[1], link.target[1]): link.properties
        for link in translation.links
        if link.type == "family_hosted_in"
    }

    assert hosted[("win.dridex", "AS13335")]["indicator_count"] == 2
    assert hosted[("win.dridex", "AS3215")]["indicator_count"] == 1
    assert hosted[("win.qakbot", "AS3215")]["indicator_count"] == 1
    assert len(hosted) == 3
    registered = {
        (link.source[1], link.target[1])
        for link in translation.links
        if link.type == "as_registered_in"
    }
    assert registered == {("AS13335", "US"), ("AS3215", "FR")}


def test_family_counts_every_recent_indicator_even_those_it_cannot_locate(translation):
    family = next(o for o in translation.objects if o.key == "win.dridex")

    # 3 located + 1 not routed + 1 domain (never resolved: that would be an active lookup)
    assert family.properties["recent_indicators"] == 5
    assert translation.skipped == 2  # the hostile family name and the nonsense entry


def test_records_fit_the_ontology(translation, ontology_path):
    ontology = load_ontology(ontology_path)

    for record in translation.objects:
        assert validate_object(ontology, record.type, record.properties) == record.properties
    for link in translation.links:
        validate_link(ontology, link.type, link.source[0], link.target[0])
    assert ontology.object_types["autonomous_system"].layer == "infrastructure"
    assert ontology.object_types["country"].layer == "territoire"


# --- fetching: the key travels in a header, read from a file ----------------------------------------


def fake_internet(seen: list[httpx.Request]):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.host == "threatfox-api.abuse.ch":
            return served(ANSWER)
        return served(TABLE)

    return httpx.MockTransport(handler)


def test_fetch_sends_the_key_in_a_header_and_returns_only_aggregable_data(tmp_path, monkeypatch):
    key_file = tmp_path / "abusech_auth_key"
    key_file.write_text("  test-key-123\n", encoding="utf-8")
    monkeypatch.setenv(KEY_FILE_ENV, str(key_file))
    seen: list[httpx.Request] = []
    connector = ThreatFoxConnector()
    client = HttpClient(connector.manifest.domains, transport=fake_internet(seen))

    result = connector.fetch(client, None)

    api_call = next(r for r in seen if r.url.host == "threatfox-api.abuse.ch")
    assert api_call.method == "POST"
    assert api_call.headers["Auth-Key"] == "test-key-123"
    assert json.loads(api_call.content) == {"query": "get_iocs", "days": 7}
    assert "test-key-123" not in str(api_call.url)
    assert b"1.0.0.7" not in result.content and b"test-key-123" not in result.content
    assert len(seen) == 2  # one query, one table: nothing per indicator


def test_source_is_off_until_a_key_is_provided(tmp_path, monkeypatch):
    monkeypatch.delenv(KEY_FILE_ENV, raising=False)
    assert ThreatFoxConnector().is_configured() is False

    monkeypatch.setenv(KEY_FILE_ENV, str(tmp_path / "absent"))
    assert ThreatFoxConnector().is_configured() is False

    (tmp_path / "empty").write_text("\n", encoding="utf-8")
    monkeypatch.setenv(KEY_FILE_ENV, str(tmp_path / "empty"))
    assert ThreatFoxConnector().is_configured() is False

    (tmp_path / "key").write_text("abc", encoding="utf-8")
    monkeypatch.setenv(KEY_FILE_ENV, str(tmp_path / "key"))
    assert ThreatFoxConnector().is_configured() is True


def test_scheduler_leaves_unconfigured_sources_alone(monkeypatch):
    monkeypatch.delenv(KEY_FILE_ENV, raising=False)

    names = runnable(mode="live")

    assert "threatfox" not in names
    assert names[0] == "kev"
    assert runnable(mode="snapshot") == ["kev"]


def test_manifest_says_the_data_cannot_be_redistributed():
    manifest = ThreatFoxConnector().manifest

    assert manifest.redistributable is False and manifest.snapshot is None
    assert set(manifest.domains) == {"threatfox-api.abuse.ch", "iptoasn.com"}


# --- HTTP client: POST obeys the same rules as GET ------------------------------------------------


def test_post_is_refused_outside_declared_hosts_and_never_follows_redirects():
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(302, headers={"Location": "https://evil.example.com/"})

    client = HttpClient(["api.example.org"], transport=httpx.MockTransport(handler))

    with pytest.raises(HttpError, match="not declared"):
        client.post_json("https://evil.example.com/", {"q": 1})
    with pytest.raises(HttpError, match="https"):
        client.post_json("http://api.example.org/", {"q": 1})
    assert calls == []
    with pytest.raises(HttpError, match="302"):
        client.post_json("https://api.example.org/", {"q": 1}, headers={"Auth-Key": "s3cret"})
    assert len(calls) == 1


def test_error_message_of_a_failed_post_never_contains_the_key():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403)

    client = HttpClient(["api.example.org"], transport=httpx.MockTransport(handler))

    with pytest.raises(HttpError) as failure:
        client.post_json("https://api.example.org/", {"q": 1}, headers={"Auth-Key": "s3cret"})

    assert "s3cret" not in str(failure.value)
