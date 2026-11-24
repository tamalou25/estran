"""Small text helpers shared by connectors."""

import re
import unicodedata
import zlib

from estran.collector.sdk import ConnectorError

_NOT_ALPHANUMERIC = re.compile(r"[^a-z0-9]+")


def slugify(text: str) -> str:
    """Turn a display name into a stable, lowercase key ('VMware vCenter' -> 'vmware-vcenter')."""
    ascii_text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    return _NOT_ALPHANUMERIC.sub("-", ascii_text.lower()).strip("-")


def bounded_gunzip(data: bytes, *, max_bytes: int) -> bytes:
    """Inflate a gzip file, refusing to produce more than `max_bytes` (see HttpClient)."""
    inflater = zlib.decompressobj(zlib.MAX_WBITS | 16)
    try:
        inflated = inflater.decompress(data, max_bytes + 1)
    except zlib.error as error:
        raise ConnectorError(f"not a valid gzip file: {error}") from error
    if len(inflated) > max_bytes or inflater.unconsumed_tail:
        raise ConnectorError(f"gzip file is larger than the {max_bytes} bytes allowed")
    return inflated
