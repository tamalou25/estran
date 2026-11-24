"""abuse.ch ThreatFox + iptoasn -> where malware families host their infrastructure.

Privacy by construction: an indicator (address, domain, URL) never leaves the fetch step.
Each address is replaced by the network that announces it; only counts per malware family
and per network are kept. The name of whoever reported an indicator is never read.

Optional source: it stays off until an abuse.ch key is provided in a file
(ESTRAN_ABUSECH_KEY_FILE). Its terms allow not-for-profit use only, and no redistribution.
"""

import bisect
import ipaddress
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any

from babel import Locale

from estran.collector.http import FetchResult, HttpClient
from estran.collector.sdk import Connector, ConnectorError, LinkRecord, ObjectRecord, Translation
from estran.collector.text import bounded_gunzip

KEY_FILE_ENV = "ESTRAN_ABUSECH_KEY_FILE"
API_URL = "https://threatfox-api.abuse.ch/api/v1/"
TABLE_URL = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"
WINDOW_DAYS = 7  # the most the API serves
MAX_TABLE_BYTES = 300 * 1024 * 1024

_FAMILY = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
_COUNTRY = re.compile(r"^[A-Z]{2}$")
_MALPEDIA = "https://malpedia.caad.fkie.fraunhofer.de/"
_COUNTRY_NAMES = Locale("fr").territories

Network = tuple[int, str, str]  # (AS number, country code, description)


class AsnTable:
    """IPv4 ranges and the network announcing each, for lookups without any network request."""

    def __init__(self, starts: list[int], ends: list[int], networks: list[Network]) -> None:
        self._starts, self._ends, self._networks = starts, ends, networks

    @classmethod
    def parse(cls, raw: bytes) -> "AsnTable":
        text = bounded_gunzip(raw, max_bytes=MAX_TABLE_BYTES).decode("utf-8", errors="replace")
        rows: list[tuple[int, int, Network]] = []
        for line in text.splitlines():
            parts = line.split("\t")
            if len(parts) != 5 or not parts[2].isdigit():
                continue
            try:
                start, end = (
                    int(ipaddress.IPv4Address(parts[0])),
                    int(ipaddress.IPv4Address(parts[1])),
                )
            except ValueError:
                continue
            rows.append((start, end, (int(parts[2]), parts[3], parts[4].strip())))
        if not rows:
            raise ConnectorError("the network table holds no usable range")
        rows.sort()
        return cls([r[0] for r in rows], [r[1] for r in rows], [r[2] for r in rows])

    def lookup(self, address: str) -> Network | None:
        try:
            value = int(ipaddress.IPv4Address(address))
        except ValueError:
            return None
        index = bisect.bisect_right(self._starts, value) - 1
        if index < 0 or value > self._ends[index]:
            return None
        network = self._networks[index]
        # AS 0 marks address space nobody announces.
        return network if network[0] > 0 and _COUNTRY.match(network[1]) else None


def reduce(raw: bytes, table: AsnTable) -> bytes:
    """Turn the API answer into what Estran may keep: family and network, no indicator."""
    try:
        answer = json.loads(raw)
    except ValueError as error:
        raise ConnectorError(f"ThreatFox answer is not valid JSON: {error}") from error
    status = answer.get("query_status") if isinstance(answer, dict) else None
    if status != "ok" or not isinstance(answer.get("data"), list):
        raise ConnectorError(f"ThreatFox refused the query: {str(status)[:60]}")

    entries: list[dict[str, Any]] = []
    skipped = 0
    for item in answer["data"]:
        family = item.get("malware") if isinstance(item, dict) else None
        if not isinstance(family, str) or not _FAMILY.match(family):
            skipped += 1
            continue
        entry: dict[str, Any] = {
            "family": family,
            "name": item.get("malware_printable"),
            "aliases": item.get("malware_alias"),
            "malpedia": item.get("malware_malpedia"),
        }
        value = item.get("ioc")
        if item.get("ioc_type") == "ip:port" and isinstance(value, str):
            network = table.lookup(value.rsplit(":", 1)[0])
            if network:
                entry["asn"], entry["country"], entry["network"] = network
        entries.append(entry)
    document = {"window_days": WINDOW_DAYS, "skipped": skipped, "entries": entries}
    return json.dumps(document, sort_keys=True).encode()


class ThreatFoxConnector(Connector):
    def is_configured(self) -> bool:
        return bool(_read_key())

    def fetch(self, client: HttpClient, etag: str | None) -> FetchResult:
        key = _read_key()
        if not key:
            raise ConnectorError(f"no abuse.ch key: put it in the file named by {KEY_FILE_ENV}")
        answer = client.post_json(
            API_URL, {"query": "get_iocs", "days": WINDOW_DAYS}, headers={"Auth-Key": key}
        )
        table = AsnTable.parse(client.get(TABLE_URL).content or b"")
        return FetchResult(content=reduce(answer, table), etag=None)

    def translate(self, raw: bytes) -> Translation:
        try:
            document = json.loads(raw)
            entries = document["entries"]
            skipped = int(document.get("skipped", 0))
        except (ValueError, KeyError, TypeError) as error:
            raise ConnectorError(f"not a reduced ThreatFox document: {error}") from error

        families: dict[str, dict[str, Any]] = {}
        networks: dict[int, tuple[str, str]] = {}
        totals: Counter[str] = Counter()
        located: Counter[tuple[str, int]] = Counter()
        for entry in entries:
            family = entry["family"]
            families.setdefault(family, entry)
            totals[family] += 1
            if isinstance(entry.get("asn"), int):
                networks[entry["asn"]] = (entry["country"], entry["network"])
                located[(family, entry["asn"])] += 1

        objects = [_family(key, families[key], totals[key]) for key in sorted(families)]
        links: list[LinkRecord] = []
        for number, (country, description) in sorted(networks.items()):
            key = f"AS{number}"
            title = description or key
            objects.append(
                ObjectRecord("autonomous_system", key, title, {"name": title, "number": number})
            )
            name = _COUNTRY_NAMES.get(country, country)
            objects.append(ObjectRecord("country", country, name, {"name": name}))
            links.append(
                LinkRecord("as_registered_in", ("autonomous_system", key), ("country", country))
            )
        for (family, number), count in sorted(located.items()):
            links.append(
                LinkRecord(
                    "family_hosted_in",
                    ("malware_family", family),
                    ("autonomous_system", f"AS{number}"),
                    {"indicator_count": count, "window_days": WINDOW_DAYS},
                )
            )
        unique = list({(o.type, o.key): o for o in objects}.values())
        return Translation(objects=unique, links=links, skipped=skipped)


def _family(key: str, entry: dict[str, Any], total: int) -> ObjectRecord:
    raw_name = entry.get("name")
    name = raw_name.strip() if isinstance(raw_name, str) and raw_name.strip() else key
    properties: dict[str, Any] = {"name": name, "recent_indicators": total}
    aliases = entry.get("aliases")
    if isinstance(aliases, str):
        properties["aliases"] = [alias.strip() for alias in aliases.split(",") if alias.strip()]
    url = entry.get("malpedia")
    if isinstance(url, str) and url.startswith(_MALPEDIA):
        properties["url"] = url
    return ObjectRecord(
        "malware_family", key, name, {k: v for k, v in properties.items() if v != []}
    )


def _read_key() -> str:
    path = os.environ.get(KEY_FILE_ENV)
    if not path:
        return ""
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return ""
