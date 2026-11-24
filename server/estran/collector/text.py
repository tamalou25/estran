"""Small text helpers shared by connectors."""

import re
import unicodedata

_NOT_ALPHANUMERIC = re.compile(r"[^a-z0-9]+")


def slugify(text: str) -> str:
    """Turn a display name into a stable, lowercase key ('VMware vCenter' -> 'vmware-vcenter')."""
    ascii_text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    return _NOT_ALPHANUMERIC.sub("-", ascii_text.lower()).strip("-")
