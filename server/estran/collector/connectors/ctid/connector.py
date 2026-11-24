"""MITRE CTID mapping of exploited vulnerabilities to ATT&CK techniques -> links only.

The mapping says two different things about a vulnerability, kept as two link types:
how it is exploited (`exploited_via`) and what the attacker can do afterwards (`enables`).
It creates no object: both ends belong to other sources.
"""

import json
import re
from typing import Any

from estran.collector.sdk import Connector, ConnectorError, LinkRecord, Translation

_LINK_OF = {
    "exploitation_technique": "exploited_via",
    "primary_impact": "enables",
    "secondary_impact": "enables",
}
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")


class KevAttackMappingConnector(Connector):
    def translate(self, raw: bytes) -> Translation:
        try:
            document = json.loads(raw)
        except ValueError as error:
            raise ConnectorError(f"mapping file is not valid JSON: {error}") from error
        entries = document.get("mapping_objects") if isinstance(document, dict) else None
        if not isinstance(entries, list):
            raise ConnectorError("mapping file has no 'mapping_objects' list")

        links: dict[tuple[str, str, str], LinkRecord] = {}
        skipped = 0
        for entry in entries:
            link = _link(entry)
            if link is None:
                skipped += 1
                continue
            links.setdefault((link.type, link.source[1], link.target[1]), link)
        return Translation(links=list(links.values()), skipped=skipped)


def _link(entry: Any) -> LinkRecord | None:
    if not isinstance(entry, dict):
        return None
    cve, technique = entry.get("capability_id"), entry.get("attack_object_id")
    link_type = _LINK_OF.get(str(entry.get("mapping_type")))
    if link_type is None or not isinstance(cve, str) or not isinstance(technique, str):
        return None
    if not _CVE.match(cve) or not _TECHNIQUE.match(technique):
        return None
    return LinkRecord(link_type, ("vulnerability", cve), ("technique", technique))
