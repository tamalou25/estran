import json

import pytest

from estran.collector.connectors.kev import KevConnector
from estran.collector.sdk import ConnectorError
from estran.ontology import load_ontology, validate_link, validate_object


@pytest.fixture(scope="module")
def sample(fixtures_dir) -> bytes:
    return (fixtures_dir / "kev_sample.json").read_bytes()


def with_entries(sample: bytes, *entries: dict) -> bytes:
    data = json.loads(sample)
    data["vulnerabilities"] = [*data["vulnerabilities"], *entries]
    return json.dumps(data).encode()


def test_manifest_declares_where_the_data_comes_from_and_its_licence():
    manifest = KevConnector().manifest

    assert manifest.id == "cisa-kev"
    assert manifest.domains == ["www.cisa.gov"]
    assert manifest.url.startswith("https://www.cisa.gov/")
    assert manifest.licence == "CC0 1.0"
    assert manifest.redistributable is True


def test_each_catalog_entry_becomes_a_vulnerability(sample):
    translation = KevConnector().translate(sample)

    vulnerabilities = {o.key: o for o in translation.objects if o.type == "vulnerability"}
    assert set(vulnerabilities) == {
        "CVE-2026-123890",
        "CVE-2026-59310",
        "CVE-2026-41709",
        "CVE-2024-10441",
        "CVE-2026-90817",
    }
    assert translation.skipped == 0


def test_vulnerability_carries_the_catalog_fields(sample):
    source = next(
        v for v in json.loads(sample)["vulnerabilities"] if v["cveID"] == "CVE-2024-10441"
    )

    translation = KevConnector().translate(sample)

    vulnerability = next(o for o in translation.objects if o.key == "CVE-2024-10441")
    assert vulnerability.title == source["vulnerabilityName"]
    assert vulnerability.properties == {
        "name": source["vulnerabilityName"],
        "description": source["shortDescription"],
        "kev_date_added": "2026-11-18",
        "ransomware_use": "known",
        "required_action": source["requiredAction"],
        "due_date": "2026-11-21",
        "cwes": ["CWE-116"],
        "notes": source["notes"],
        "cve_url": "https://www.cve.org/CVERecord?id=CVE-2024-10441",
    }


def test_products_and_vendors_are_created_once_each(sample):
    translation = KevConnector().translate(sample)

    products = sorted(o.key for o in translation.objects if o.type == "product")
    vendors = sorted(o.key for o in translation.objects if o.type == "vendor")
    assert products == [
        "broadcom:vmware-esx",
        "broadcom:vmware-vcenter",
        "synology:diskstation-manager-dsm",
        "vanderbilt-university:research-electronic-data-capture-redcap",
    ]
    assert vendors == ["broadcom", "synology", "vanderbilt-university"]
    titles = {o.key: o.title for o in translation.objects}
    assert titles["broadcom:vmware-vcenter"] == "VMware vCenter"
    assert titles["broadcom"] == "Broadcom"


def test_vulnerabilities_products_and_vendors_are_linked(sample):
    translation = KevConnector().translate(sample)

    links = {(link.type, link.source, link.target) for link in translation.links}
    assert (
        "affects",
        ("vulnerability", "CVE-2026-59310"),
        ("product", "broadcom:vmware-vcenter"),
    ) in links
    assert ("made_by", ("product", "broadcom:vmware-esx"), ("vendor", "broadcom")) in links
    assert len([link for link in translation.links if link.type == "affects"]) == 5
    assert len([link for link in translation.links if link.type == "made_by"]) == 4
    assert {link.nature for link in translation.links} == {"fact"}


def test_every_record_fits_the_project_ontology(sample, ontology_path):
    ontology = load_ontology(ontology_path)

    translation = KevConnector().translate(sample)

    for record in translation.objects:
        assert validate_object(ontology, record.type, record.properties) == record.properties
    for link in translation.links:
        validate_link(ontology, link.type, link.source[0], link.target[0])


@pytest.mark.parametrize(
    "broken",
    [
        {"cveID": "not-a-cve", "vendorProject": "Acme", "product": "Rocket"},
        {"vendorProject": "Acme", "product": "Rocket"},
        {"cveID": "CVE-2025-0001", "vendorProject": "", "product": "Rocket"},
        {"cveID": "CVE-2025-0001", "vendorProject": "Acme", "product": "???"},
        {"cveID": "CVE-2025-0001", "vendorProject": "Acme", "product": "Rocket",
         "vulnerabilityName": "Bad date", "dateAdded": "yesterday"},
        "not even an object",
    ],
)  # fmt: skip
def test_unusable_entry_is_skipped_and_counted_without_losing_the_others(sample, broken):
    translation = KevConnector().translate(with_entries(sample, broken))

    assert translation.skipped == 1
    assert len([o for o in translation.objects if o.type == "vulnerability"]) == 5
    assert all(o.key != "CVE-2025-0001" for o in translation.objects)
    assert all(o.key != "acme" for o in translation.objects)


def test_entry_with_unknown_optional_values_is_kept(sample):
    entry = {
        "cveID": "CVE-2025-0002",
        "vendorProject": "Acme",
        "product": "Rocket",
        "vulnerabilityName": "Acme Rocket Overflow",
        "knownRansomwareCampaignUse": "Suspected",
    }

    translation = KevConnector().translate(with_entries(sample, entry))

    vulnerability = next(o for o in translation.objects if o.key == "CVE-2025-0002")
    assert "ransomware_use" not in vulnerability.properties
    assert translation.skipped == 0


@pytest.mark.parametrize("raw", [b"<html>maintenance</html>", b'{"count": 3}', b"[]"])
def test_document_that_is_not_a_catalog_is_an_error(raw):
    with pytest.raises(ConnectorError):
        KevConnector().translate(raw)
