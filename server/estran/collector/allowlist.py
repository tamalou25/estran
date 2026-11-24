"""The list of hosts the egress proxy lets through, derived from the connector manifests.

A connector can only reach the domains it declares: the HTTP client checks it in the
application, and the proxy enforces it on the network with the file rendered here.
"""

from estran.collector.connectors import REGISTRY

HEADER = (
    "# Fichier généré : ne pas modifier à la main.\n"
    "# Hôtes que le proxy sortant laisse joindre, tirés des manifestes des connecteurs.\n"
    "# Régénérer : python -m estran.collector allowlist --write infra/proxy/allowlist.txt\n"
)


def allowed_domains() -> list[str]:
    return sorted({domain for cls in REGISTRY.values() for domain in cls.manifest.domains})


def render() -> str:
    return HEADER + "".join(f"{domain}\n" for domain in allowed_domains())
