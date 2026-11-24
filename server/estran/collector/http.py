"""The only door to the Internet: HTTPS, declared hosts only, bounded size, no redirects."""

from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from estran import __version__

USER_AGENT = f"Estran/{__version__} (open-data collector)"
DEFAULT_MAX_BYTES = 50 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 30.0


class HttpError(Exception):
    """A request was refused by policy or failed."""


@dataclass(frozen=True, slots=True)
class FetchResult:
    content: bytes | None
    etag: str | None
    not_modified: bool = False


class HttpClient:
    """HTTP client restricted to the domains a connector declares in its manifest.

    Proxy settings come from the environment (HTTPS_PROXY), which is how the egress proxy
    of the hardened deployment is plugged in.
    """

    def __init__(
        self,
        allowed_domains: list[str],
        *,
        transport: httpx.BaseTransport | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._allowed = {domain.lower() for domain in allowed_domains}
        self._max_bytes = max_bytes
        self._client = httpx.Client(
            transport=transport,
            timeout=timeout,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
        )

    def close(self) -> None:
        self._client.close()

    def get(self, url: str, *, etag: str | None = None) -> FetchResult:
        self._check_allowed(url)
        headers = {"If-None-Match": etag} if etag else {}
        try:
            with self._client.stream("GET", url, headers=headers) as response:
                if response.status_code == httpx.codes.NOT_MODIFIED:
                    return FetchResult(content=None, etag=etag, not_modified=True)
                if response.status_code != httpx.codes.OK:
                    raise HttpError(f"{url} answered HTTP {response.status_code}")
                content = self._read_bounded(url, response)
                return FetchResult(content=content, etag=response.headers.get("ETag"))
        except httpx.HTTPError as error:
            raise HttpError(f"{url} could not be fetched: {error}") from error

    def _check_allowed(self, url: str) -> None:
        parts = urlsplit(url)
        if parts.scheme != "https":
            raise HttpError(f"{url} refused: only https is allowed")
        if (parts.hostname or "").lower() not in self._allowed or parts.username is not None:
            raise HttpError(f"{url} refused: host not declared in the connector manifest")

    def _read_bounded(self, url: str, response: httpx.Response) -> bytes:
        body = bytearray()
        for chunk in response.iter_bytes():
            body += chunk
            if len(body) > self._max_bytes:
                raise HttpError(f"{url} is larger than the {self._max_bytes} bytes allowed")
        return bytes(body)
