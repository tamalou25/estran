"""Registry of available connectors, by the short name used on the command line."""

from estran.collector.connectors.kev import KevConnector
from estran.collector.sdk import Connector

REGISTRY: dict[str, type[Connector]] = {
    "kev": KevConnector,
}
