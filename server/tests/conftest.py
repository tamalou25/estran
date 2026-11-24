from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def ontology_path() -> Path:
    return REPO_ROOT / "ontology" / "ontology.yaml"


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return FIXTURES
