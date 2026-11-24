"""CISA KEV catalog -> vulnerabilities, the products they affect and their vendors."""

import json
import re
from datetime import date
from typing import Any

from estran.collector.sdk import Connector, ConnectorError, LinkRecord, ObjectRecord, Translation
from estran.collector.text import slugify

_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
_RANSOMWARE = {"known": "known", "unknown": "unknown"}


class _Unusable(Exception):
    """One catalog entry cannot be translated; the others still can."""


class KevConnector(Connector):
    def translate(self, raw: bytes) -> Translation:
        try:
            document = json.loads(raw)
        except ValueError as error:
            raise ConnectorError(f"KEV catalog is not valid JSON: {error}") from error
        entries = document.get("vulnerabilities") if isinstance(document, dict) else None
        if not isinstance(entries, list):
            raise ConnectorError("KEV catalog has no 'vulnerabilities' list")

        objects: dict[tuple[str, str], ObjectRecord] = {}
        links: dict[tuple[str, str, str], LinkRecord] = {}
        skipped = 0
        for entry in entries:
            try:
                entry_objects, entry_links = _translate_entry(entry)
            except _Unusable:
                skipped += 1
                continue
            for record in entry_objects:
                objects.setdefault((record.type, record.key), record)
            for link in entry_links:
                links.setdefault((link.type, link.source[1], link.target[1]), link)
        return Translation(list(objects.values()), list(links.values()), skipped)


def _translate_entry(entry: Any) -> tuple[list[ObjectRecord], list[LinkRecord]]:
    if not isinstance(entry, dict):
        raise _Unusable

    cve_id = _text(entry, "cveID")
    vendor_name = _text(entry, "vendorProject")
    product_name = _text(entry, "product")
    vendor_key = slugify(vendor_name)
    product_slug = slugify(product_name)
    if not _CVE_ID.match(cve_id) or not vendor_key or not product_slug:
        raise _Unusable
    product_key = f"{vendor_key}:{product_slug}"

    name = _text(entry, "vulnerabilityName") or cve_id
    cwes = entry.get("cwes")
    properties: dict[str, Any] = {
        "name": name,
        "description": _text(entry, "shortDescription"),
        "kev_date_added": _date(entry, "dateAdded"),
        "ransomware_use": _RANSOMWARE.get(_text(entry, "knownRansomwareCampaignUse").lower()),
        "required_action": _text(entry, "requiredAction"),
        "due_date": _date(entry, "dueDate"),
        "cwes": [c.strip() for c in cwes if isinstance(c, str) and c.strip()]
        if isinstance(cwes, list)
        else [],
        "notes": _text(entry, "notes"),
        "cve_url": f"https://www.cve.org/CVERecord?id={cve_id}",
    }
    properties = {key: value for key, value in properties.items() if value}

    vulnerability = ("vulnerability", cve_id)
    product = ("product", product_key)
    vendor = ("vendor", vendor_key)
    return (
        [
            ObjectRecord("vulnerability", cve_id, name, properties),
            ObjectRecord("product", product_key, product_name, {"name": product_name}),
            ObjectRecord("vendor", vendor_key, vendor_name, {"name": vendor_name}),
        ],
        [LinkRecord("affects", vulnerability, product), LinkRecord("made_by", product, vendor)],
    )


def _text(entry: dict[str, Any], field: str) -> str:
    value = entry.get(field)
    return value.strip() if isinstance(value, str) else ""


def _date(entry: dict[str, Any], field: str) -> str | None:
    text = _text(entry, field)
    if not text:
        return None
    try:
        if len(text) != 10:
            raise ValueError(text)
        return date.fromisoformat(text).isoformat()
    except ValueError:
        raise _Unusable from None
