import httpx
import pytest

from estran.collector.http import HttpClient, HttpError


def client_answering(handler, **options) -> HttpClient:
    return HttpClient(["data.example.org"], transport=httpx.MockTransport(handler), **options)


def test_body_and_etag_are_returned_on_success():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"payload", headers={"ETag": '"v1"'})

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
        return httpx.Response(200, content=b"x")

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


def test_redirect_is_not_followed():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://evil.example.com/"})

    with pytest.raises(HttpError, match="302"):
        client_answering(handler).get("https://data.example.org/feed.json")


def test_server_error_is_reported():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    with pytest.raises(HttpError, match="503"):
        client_answering(handler).get("https://data.example.org/feed.json")


def test_oversized_body_is_refused():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 2048)

    with pytest.raises(HttpError, match="larger"):
        client_answering(handler, max_bytes=1024).get("https://data.example.org/feed.json")


def test_network_failure_is_reported_as_http_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    with pytest.raises(HttpError, match="no route"):
        client_answering(handler).get("https://data.example.org/feed.json")
