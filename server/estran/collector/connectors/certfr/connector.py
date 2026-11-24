"""CERT-FR alerts (RSS feed) -> alerts, linked to the vulnerabilities they name.

Only alerts are collected: their feed cites the CVE identifiers, which the advisory feed
does not. The feed is parsed with defusedxml: entity declarations are refused outright.
"""

import re
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from estran.collector.sdk import Connector, ConnectorError, LinkRecord, ObjectRecord, Translation

if TYPE_CHECKING:  # the type only: all parsing goes through defusedxml
    from xml.etree.ElementTree import Element  # noqa: S405

_ALERT_URL = re.compile(r"^https://www\.cert\.cyber\.gouv\.fr/alerte/(CERTFR-\d{4}-ALE-\d+)/?$")
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_DATE_SUFFIX = re.compile(r"\s*\(\d{1,2}(er)? \S+ \d{4}\)\s*$")


class CertFrAlertsConnector(Connector):
    def translate(self, raw: bytes) -> Translation:
        try:
            root = ElementTree.fromstring(raw)
        except (ElementTree.ParseError, DefusedXmlException, ValueError) as error:
            raise ConnectorError(f"CERT-FR feed is not plain XML: {error}") from error
        channel = root.find("channel") if root.tag == "rss" else None
        if channel is None:
            raise ConnectorError("CERT-FR feed is not an RSS document")

        objects: list[ObjectRecord] = []
        links: list[LinkRecord] = []
        skipped = 0
        for item in channel.findall("item"):
            title, link = _text(item, "title"), _text(item, "link")
            match = _ALERT_URL.match(link)
            if match is None or not title:
                skipped += 1
                continue
            key = match.group(1)
            description = _text(item, "description")
            name = _DATE_SUFFIX.sub("", title)
            properties = {"name": name, "description": description, "url": link}
            published = _date(_text(item, "pubDate"))
            if published:
                properties["published"] = published
            objects.append(
                ObjectRecord("alert", key, name, {k: v for k, v in properties.items() if v})
            )
            for cve in sorted(set(_CVE.findall(f"{title} {description}"))):
                links.append(LinkRecord("alert_mentions", ("alert", key), ("vulnerability", cve)))
        return Translation(objects=objects, links=links, skipped=skipped)


def _text(item: "Element", tag: str) -> str:
    return (item.findtext(tag) or "").strip()


def _date(text: str) -> str:
    try:
        parsed: datetime = parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return ""
    return parsed.date().isoformat()
