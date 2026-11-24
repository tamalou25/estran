"""The only door to the Internet: HTTPS, declared hosts only, bounded size, no redirects."""

import zlib
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import httpx

from estran import __version__

USER_AGENT = f"Estran/{__version__} (open-data collector)"
DEFAULT_MAX_BYTES = 50 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 30.0
MAX_REDIRECTS = 3
REDIRECT_CODES = (301, 302, 303, 307, 308)


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
            # Only gzip is advertised: it is the one encoding inflated under a size limit here.
            headers={"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"},
        )

    def close(self) -> None:
        self._client.close()

    def get(self, url: str, *, etag: str | None = None) -> FetchResult:
        headers = {"If-None-Match": etag} if etag else {}
        # A redirect is followed by hand, so that every hop goes through the same check as
        # the first address: https, and a host the connector declared.
        for _ in range(MAX_REDIRECTS + 1):
            self._check_allowed(url)
            try:
                with self._client.stream("GET", url, headers=headers) as response:
                    if response.status_code == httpx.codes.NOT_MODIFIED:
                        return FetchResult(content=None, etag=etag, not_modified=True)
                    if response.status_code in REDIRECT_CODES:
                        url = urljoin(url, response.headers.get("Location", ""))
                        continue
                    if response.status_code != httpx.codes.OK:
                        raise HttpError(f"{url} answered HTTP {response.status_code}")
                    content = self._read_bounded(url, response)
                    return FetchResult(content=content, etag=response.headers.get("ETag"))
            except httpx.HTTPError as error:
                raise HttpError(f"{url} could not be fetched: {error}") from error
        raise HttpError(f"{url}: more than {MAX_REDIRECTS} redirects")

    def post_json(
        self, url: str, payload: dict[str, object], *, headers: dict[str, str] | None = None
    ) -> bytes:
        """POST a JSON body. Same rules as `get`; a redirect is an error, never followed.

        `headers` may carry a credential: nothing from them ever goes into an error message.
        """
        self._check_allowed(url)
        try:
            with self._client.stream("POST", url, json=payload, headers=headers or {}) as response:
                if response.status_code != httpx.codes.OK:
                    raise HttpError(f"{url} answered HTTP {response.status_code}")
                return self._read_bounded(url, response)
        except httpx.HTTPError as error:
            raise HttpError(f"{url} could not be fetched: {type(error).__name__}") from error

    def _check_allowed(self, url: str) -> None:
        parts = urlsplit(url)
        if parts.scheme != "https":
            raise HttpError(f"{url} refused: only https is allowed")
        if (parts.hostname or "").lower() not in self._allowed or parts.username is not None:
            raise HttpError(f"{url} refused: host not declared in the connector manifest")

    def _read_bounded(self, url: str, response: httpx.Response) -> bytes:
        """Read the body without ever holding more than the limit, compressed or not.

        The raw stream is read and inflated here, step by step, instead of letting the HTTP
        library decompress: a few kilobytes of gzip can expand to gigabytes.
        """
        encoding = response.headers.get("Content-Encoding", "identity").strip().lower()
        if encoding not in ("identity", "gzip"):
            raise HttpError(f"{url} uses content encoding '{encoding}', which is not accepted")
        inflater = zlib.decompressobj(zlib.MAX_WBITS | 16) if encoding == "gzip" else None
        too_large = HttpError(f"{url} is larger than the {self._max_bytes} bytes allowed")

        body = bytearray()
        for chunk in response.iter_raw():
            if inflater is None:
                body += chunk
            else:
                try:
                    # at most one byte over the limit is ever produced
                    body += inflater.decompress(chunk, self._max_bytes + 1 - len(body))
                except zlib.error as error:
                    raise HttpError(f"{url} sent invalid gzip data: {error}") from error
                if inflater.unconsumed_tail:
                    raise too_large
            if len(body) > self._max_bytes:
                raise too_large
        return bytes(body)
