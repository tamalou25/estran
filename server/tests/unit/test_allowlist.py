"""The egress proxy lets the collector reach only what the connector manifests declare."""

from estran.collector.allowlist import allowed_domains, render
from estran.collector.connectors import REGISTRY

HEADER_PREFIX = "#"


def test_allowlist_is_exactly_the_domains_declared_by_the_connectors():
    declared = {domain for connector in REGISTRY.values() for domain in connector.manifest.domains}

    assert allowed_domains() == sorted(declared)
    assert "www.cisa.gov" in allowed_domains()


def test_allowlist_holds_plain_host_names_only():
    for domain in allowed_domains():
        # no wildcard, no leading dot (which would allow every sub-domain), no scheme or path
        assert domain == domain.lower().strip()
        assert not domain.startswith(".")
        assert all(part.replace("-", "").isalnum() for part in domain.split("."))


def test_committed_proxy_allowlist_is_in_sync_with_the_manifests(repo_root):
    """Adding a connector domain without regenerating the proxy file must fail the build.

    Regenerate with: python -m estran.collector allowlist --write infra/proxy/allowlist.txt
    """
    committed = (repo_root / "infra" / "proxy" / "allowlist.txt").read_text(encoding="utf-8")

    assert committed == render()


def test_rendered_file_explains_itself_and_lists_one_domain_per_line():
    lines = render().splitlines()

    assert lines[0].startswith(HEADER_PREFIX)
    assert [line for line in lines if not line.startswith(HEADER_PREFIX)] == allowed_domains()
    assert render().endswith("\n")
