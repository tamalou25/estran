"""Helpers shared by the tests."""

import httpx


def served(body: bytes, headers: dict[str, str] | None = None) -> httpx.Response:
    """A 200 answer whose body is still on the wire, as a real server's is.

    `httpx.Response(200, content=...)` would be already read and already decoded, which is
    not what the collector meets in production and hides how it handles the raw stream.
    """
    return httpx.Response(200, headers=headers, stream=httpx.ByteStream(body))
