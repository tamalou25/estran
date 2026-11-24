"""NIST NVD -> severity (CVSS) and publication date of the exploited vulnerabilities.

Only the CVEs of the KEV catalog are asked for (`hasKev`): one or two requests instead of
one per vulnerability, and exactly the subset the NVD still analyses in full.
It creates no object: it adds fields to vulnerabilities the KEV connector created.
"""

import json
import time
from collections.abc import Iterator
from typing import Any, ClassVar

from estran.collector.http import FetchResult, HttpClient
from estran.collector.sdk import Connector, ConnectorError, EnrichmentRecord, Translation

# Most recent scoring system first.
_METRICS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
_SEVERITIES = {"critical", "high", "medium", "low", "none"}
MAX_PAGES = 20


class NvdConnector(Connector):
    page_size: ClassVar[int] = 2000  # the largest page the API serves
    # Public rate limit without an API key: 5 requests per 30 seconds.
    pause_seconds: ClassVar[float] = 6.5

    def fetch(self, client: HttpClient, etag: str | None) -> FetchResult:
        """Read every page, pausing between requests, and return them merged."""
        entries: list[Any] = []
        for page in range(MAX_PAGES):
            if page:
                time.sleep(self.pause_seconds)
            url = f"{self.manifest.url}&resultsPerPage={self.page_size}&startIndex={len(entries)}"
            content = client.get(url).content or b""
            try:
                document = json.loads(content)
                batch = document["vulnerabilities"]
                total = int(document["totalResults"])
            except (ValueError, KeyError, TypeError) as error:
                raise ConnectorError(f"NVD answer is not the expected JSON: {error}") from error
            entries += batch
            if not batch or len(entries) >= total:
                break
        return FetchResult(content=json.dumps({"vulnerabilities": entries}).encode(), etag=None)

    def translate(self, raw: bytes) -> Translation:
        try:
            document = json.loads(raw)
        except ValueError as error:
            raise ConnectorError(f"NVD document is not valid JSON: {error}") from error
        entries = document.get("vulnerabilities") if isinstance(document, dict) else None
        if not isinstance(entries, list):
            raise ConnectorError("NVD document has no 'vulnerabilities' list")
        return Translation(enrichments=_enrichments(entries))


def _enrichments(entries: list[Any]) -> Iterator[EnrichmentRecord]:
    for entry in entries:
        cve = entry.get("cve") if isinstance(entry, dict) else None
        if not isinstance(cve, dict) or not isinstance(cve.get("id"), str):
            continue
        properties = _severity(cve.get("metrics"))
        published = cve.get("published")
        if isinstance(published, str) and len(published) >= 10:
            properties["published"] = published[:10]
        if properties:
            yield EnrichmentRecord("vulnerability", cve["id"], properties)


def _severity(metrics: Any) -> dict[str, Any]:
    if not isinstance(metrics, dict):
        return {}
    for name in _METRICS:
        candidates = [m for m in metrics.get(name) or [] if isinstance(m, dict)]
        if not candidates:
            continue
        # The NVD's own analysis ("Primary") rather than the vendor's, when both exist.
        metric = next((m for m in candidates if m.get("type") == "Primary"), candidates[0])
        data = metric.get("cvssData")
        if not isinstance(data, dict):
            continue
        score = data.get("baseScore")
        # CVSS 2 carries its severity next to the data, later versions inside it.
        severity = str(data.get("baseSeverity") or metric.get("baseSeverity") or "").lower()
        properties: dict[str, Any] = {
            "cvss_score": score,
            "cvss_version": data.get("version"),
            "cvss_vector": data.get("vectorString"),
        }
        if severity in _SEVERITIES:
            properties["cvss_severity"] = severity
        return {k: v for k, v in properties.items() if v not in (None, "")}
    return {}
