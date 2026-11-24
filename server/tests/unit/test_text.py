import pytest

from estran.collector.text import slugify


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("VMware vCenter", "vmware-vcenter"),
        ("DiskStation Manager (DSM)", "diskstation-manager-dsm"),
        ("  .NET  Framework ", "net-framework"),
        ("Éditeur Âgé", "editeur-age"),
        ("Windows 10", "windows-10"),
        ("???", ""),
        ("", ""),
    ],
)
def test_slugify_makes_a_stable_key_from_a_name(text, expected):
    assert slugify(text) == expected
