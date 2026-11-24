import gzip
import zlib

import httpx
import pytest
from support import served

from estran.collector.http import HttpClient, HttpError


def client_answering(handler, **options) -> HttpClient:
    return HttpClient(["data.example.org"], transport=httpx.MockTransport(handler), **options)


def test_body_and_etag_are_returned_on_success():
    def handler(request: httpx.Request) -> httpx.Response:
        return served(b"payload", headers={"ETag": '"v1"'})

    result = client_answering(handler).get("https://data.example.org/feed.json")

    assert result.content == b"payload"
    assert result.etag == '"v1"'
    assert result.not_modified is False


def test_known_etag_is_sent_and_unchanged_content_is_reported():
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("If-None-Match"))
        return httpx.Response(304)

    result = client_answering(handler).get("https://data.example.org/feed.json", etag='"v1"')

    assert seen == ['"v1"']
    assert result.not_modified is True
    assert result.content is None
    assert result.etag == '"v1"'


def test_request_identifies_the_collector():
    agents: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        agents.append(request.headers["User-Agent"])
        return served(b"x")

    client_answering(handler).get("https://data.example.org/feed.json")

    assert agents[0].startswith("Estran/")


def never_called(request: httpx.Request) -> httpx.Response:
    raise AssertionError(f"no request should have been sent, got {request.url}")


def test_plain_http_is_refused_before_any_request():
    with pytest.raises(HttpError, match="https"):
        client_answering(never_called).get("http://data.example.org/feed.json")


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example.com/feed.json",
        "https://data.example.org.evil.example.com/feed.json",
        "https://data.example.org@evil.example.com/feed.json",
    ],
)
def test_host_outside_the_declared_domains_is_refused_before_any_request(url):
    with pytest.raises(HttpError, match="not declared"):
        client_answering(never_called).get(url)


def test_redirect_towards_an_undeclared_host_is_not_followed():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://evil.example.com/"})

    with pytest.raises(HttpError, match="not declared"):
        client_answering(handler).get("https://data.example.org/feed.json")


def test_server_error_is_reported():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    with pytest.raises(HttpError, match="503"):
        client_answering(handler).get("https://data.example.org/feed.json")


def test_oversized_body_is_refused():
    def handler(request: httpx.Request) -> httpx.Response:
        return served(b"x" * 2048)

    with pytest.raises(HttpError, match="larger"):
        client_answering(handler, max_bytes=1024).get("https://data.example.org/feed.json")


def test_network_failure_is_reported_as_http_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    with pytest.raises(HttpError, match="no route"):
        client_answering(handler).get("https://data.example.org/feed.json")


# --- compressed answers: the size limit applies to what ends up in memory -----------------


def test_gzip_answer_is_decompressed():
    def handler(request: httpx.Request) -> httpx.Response:
        return served(gzip.compress(b"payload" * 100), headers={"Content-Encoding": "gzip"})

    result = client_answering(handler).get("https://data.example.org/feed.json")

    assert result.content == b"payload" * 100


def test_request_only_advertises_the_encoding_it_can_bound():
    encodings: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        encodings.append(request.headers["Accept-Encoding"])
        return served(b"x")

    client_answering(handler).get("https://data.example.org/feed.json")

    assert encodings == ["gzip"]


def test_small_download_that_inflates_beyond_the_limit_is_refused():
    bomb = gzip.compress(b"\0" * 5_000_000)
    assert len(bomb) < 10_000  # passes any limit on downloaded bytes

    def handler(request: httpx.Request) -> httpx.Response:
        return served(bomb, headers={"Content-Encoding": "gzip"})

    with pytest.raises(HttpError, match="larger"):
        client_answering(handler, max_bytes=100_000).get("https://data.example.org/feed.json")


def test_inflating_stops_as_soon_as_the_limit_is_passed(monkeypatch):
    produced: list[int] = []
    real = zlib.decompressobj

    class Spy:
        def __init__(self, *args):
            self._inner = real(*args)

        def decompress(self, data, max_length=0):
            out = self._inner.decompress(data, max_length)
            produced.append(len(out))
            return out

        def __getattr__(self, name):
            return getattr(self._inner, name)

    monkeypatch.setattr(zlib, "decompressobj", Spy)
    bomb = gzip.compress(b"\0" * 5_000_000)

    def handler(request: httpx.Request) -> httpx.Response:
        return served(bomb, headers={"Content-Encoding": "gzip"})

    with pytest.raises(HttpError, match="larger"):
        client_answering(handler, max_bytes=100_000).get("https://data.example.org/feed.json")

    assert sum(produced) <= 100_001


def test_corrupt_gzip_answer_is_reported():
    def handler(request: httpx.Request) -> httpx.Response:
        return served(b"not gzip", headers={"Content-Encoding": "gzip"})

    with pytest.raises(HttpError, match="gzip"):
        client_answering(handler).get("https://data.example.org/feed.json")


def test_encoding_that_cannot_be_bounded_is_refused():
    def handler(request: httpx.Request) -> httpx.Response:
        return served(b"\x0b\x02\x80hi\x03", headers={"Content-Encoding": "br"})

    with pytest.raises(HttpError, match="encoding"):
        client_answering(handler).get("https://data.example.org/feed.json")
