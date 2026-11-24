"""FIRST EPSS -> probability that a vulnerability is exploited in the next 30 days.

The file scores every published CVE (hundreds of thousands). Records are produced lazily and
only those about vulnerabilities Estran already holds are kept: it creates no object.
"""

import re
from collections.abc import Iterator
from typing import Any

from estran.collector.sdk import Connector, ConnectorError, EnrichmentRecord, Translation
from estran.collector.text import bounded_gunzip

MAX_INFLATED_BYTES = 200 * 1024 * 1024
_HEADER = "cve,epss,percentile"
_SCORE_DATE = re.compile(r"score_date:(\d{4}-\d{2}-\d{2})")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


class EpssConnector(Connector):
    def translate(self, raw: bytes) -> Translation:
        try:
            lines = bounded_gunzip(raw, max_bytes=MAX_INFLATED_BYTES).decode("utf-8").splitlines()
        except UnicodeDecodeError as error:
            raise ConnectorError(f"EPSS file is not text: {error}") from error
        # First line: a comment giving the model version and the date of the scores.
        date = _SCORE_DATE.search(lines[0]) if lines and lines[0].startswith("#") else None
        if date is None or len(lines) < 2 or lines[1].strip() != _HEADER:
            raise ConnectorError(f"EPSS file does not start with a dated comment and '{_HEADER}'")
        return Translation(enrichments=_enrichments(lines[2:], date.group(1)))


def _enrichments(lines: list[str], score_date: str) -> Iterator[EnrichmentRecord]:
    for line in lines:
        parts = line.strip().split(",")
        if len(parts) != 3 or not _CVE.match(parts[0]):
            continue
        yield EnrichmentRecord(
            "vulnerability",
            parts[0],
            {
                "epss_score": _number(parts[1]),
                "epss_percentile": _number(parts[2]),
                "epss_date": score_date,
            },
        )


def _number(text: str) -> Any:
    """A float, or the raw text so that the ontology check rejects and counts the row."""
    try:
        return float(text)
    except ValueError:
        return text
