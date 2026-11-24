"""Registry of available connectors, by the short name used on the command line.

Order matters: a source is listed before the ones that build on it (`after` in a manifest),
so that a first start fills the store in one pass. A test enforces it.
"""

from estran.collector.connectors.attack import AttackConnector
from estran.collector.connectors.certfr import CertFrAlertsConnector
from estran.collector.connectors.ctid import KevAttackMappingConnector
from estran.collector.connectors.epss import EpssConnector
from estran.collector.connectors.kev import KevConnector
from estran.collector.connectors.nvd import NvdConnector
from estran.collector.sdk import Connector

REGISTRY: dict[str, type[Connector]] = {
    "kev": KevConnector,
    "attack": AttackConnector,
    "attack-kev": KevAttackMappingConnector,
    "nvd": NvdConnector,
    "epss": EpssConnector,
    "certfr": CertFrAlertsConnector,
}
