"""Engine pieces added for the Threat layer: safe redirects, partial updates, dependencies."""

import gzip

import httpx
import pytest
from support import served

from estran.collector.http import HttpClient, HttpError
from estran.collector.scheduler import dependents
from estran.collector.sdk import ConnectorError, Manifest
from estran.collector.text import bounded_gunzip
from estran.ontology import RecordError, load_ontology, validate_properties

# --- redirects: followed only towards a declared host, over https, a few times ---------------


def client_with(routes: dict[str, httpx.Response], **options) -> tuple[HttpClient, list[str]]:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return routes[str(request.url)]

    domains = ["data.example.org", "files.example.org"]
    return HttpClient(domains, transport=httpx.MockTransport(handler), **options), seen


def redirect(location: str, status: int = 302) -> httpx.Response:
    return httpx.Response(status, headers={"Location": location})


def test_redirect_to_a_declared_host_is_followed():
    client, seen = client_with(
        {
            "https://data.example.org/current": redirect("https://files.example.org/2026-11-23"),
            "https://files.example.org/2026-11-23": served(b"payload", {"ETag": '"d1"'}),
        }
    )

    result = client.get("https://data.example.org/current")

    assert result.content == b"payload"
    assert result.etag == '"d1"'
    assert seen == ["https://data.example.org/current", "https://files.example.org/2026-11-23"]


def test_relative_redirect_stays_on_the_same_host():
    client, seen = client_with(
        {
            "https://data.example.org/current": redirect("/dated/file.csv", 307),
            "https://data.example.org/dated/file.csv": served(b"x"),
        }
    )

    assert client.get("https://data.example.org/current").content == b"x"
    assert seen[-1] == "https://data.example.org/dated/file.csv"


@pytest.mark.parametrize(
    "location",
    [
        "https://evil.example.com/steal",
        "http://data.example.org/plain",
        "//evil.example.com/x",
        "file:///etc/passwd",
    ],
)
def test_redirect_towards_anything_else_is_refused_without_a_request(location):
    client, seen = client_with({"https://data.example.org/current": redirect(location)})

    with pytest.raises(HttpError, match="refused"):
        client.get("https://data.example.org/current")

    assert seen == ["https://data.example.org/current"]


def test_redirect_loop_is_cut():
    client, seen = client_with(
        {
            "https://data.example.org/a": redirect("https://data.example.org/b"),
            "https://data.example.org/b": redirect("https://data.example.org/a"),
        }
    )

    with pytest.raises(HttpError, match="redirect"):
        client.get("https://data.example.org/a")

    assert len(seen) <= 4


# --- gzip files (not gzip transfer): same rule, never inflate past the limit -----------------


def test_gzip_file_is_inflated():
    assert bounded_gunzip(gzip.compress(b"cve,epss\n" * 10), max_bytes=1000) == b"cve,epss\n" * 10


def test_gzip_file_inflating_past_the_limit_is_refused():
    with pytest.raises(ConnectorError, match="larger"):
        bounded_gunzip(gzip.compress(b"\0" * 5_000_000), max_bytes=100_000)


def test_file_that_is_not_gzip_is_refused():
    with pytest.raises(ConnectorError, match="gzip"):
        bounded_gunzip(b"plain text", max_bytes=1000)


# --- partial updates: checked against the ontology, without requiring the whole object -------


def test_partial_update_does_not_need_the_required_properties(ontology_path):
    ontology = load_ontology(ontology_path)

    assert validate_properties(ontology, "vulnerability", {"epss_score": 0.5}) == {
        "epss_score": 0.5
    }


@pytest.mark.parametrize(
    "properties",
    [{"owner": "someone"}, {"epss_score": "high"}, {"cvss_severity": "catastrophic"}],
)
def test_partial_update_is_still_checked_against_the_ontology(ontology_path, properties):
    ontology = load_ontology(ontology_path)

    with pytest.raises(RecordError):
        validate_properties(ontology, "vulnerability", properties)


def test_partial_update_of_an_unknown_type_is_refused(ontology_path):
    with pytest.raises(RecordError, match="spaceship"):
        validate_properties(load_ontology(ontology_path), "spaceship", {"name": "x"})


# --- manifests and dependencies ---------------------------------------------------------------

BASE = {
    "id": "x",
    "name": "X",
    "version": "1",
    "url": "https://data.example.org/x",
    "homepage": "https://data.example.org/",
    "domains": ["data.example.org"],
    "licence": "CC0 1.0",
    "licence_url": "https://data.example.org/licence",
    "attribution": "X",
    "redistributable": True,
    "schedule_hours": 24,
}


def manifest(**changes) -> Manifest:
    return Manifest.model_validate({**BASE, **changes})


def test_manifest_defaults_keep_downloads_modest():
    assert manifest().max_megabytes == 50
    assert manifest().after == []
    assert manifest().enriches == []


def test_connectors_that_build_on_a_source_are_found():
    manifests = {
        "kev": manifest(id="cisa-kev"),
        "attack": manifest(id="mitre-attack"),
        "mapping": manifest(id="mapping", after=["cisa-kev", "mitre-attack"]),
        "epss": manifest(id="epss", after=["cisa-kev"]),
    }

    assert dependents(manifests, "cisa-kev") == ["mapping", "epss"]
    assert dependents(manifests, "mitre-attack") == ["mapping"]
    assert dependents(manifests, "epss") == []
