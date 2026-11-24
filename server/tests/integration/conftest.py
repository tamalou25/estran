"""Integration tests run against a real PostGIS database (never mocked).

They need ESTRAN_TEST_DATABASE_URL, which `compose.test.yaml` provides. Without it they are
skipped, so the unit tests can still run anywhere.
"""

import os
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine, text

from estran.db.engine import create_db_engine
from estran.db.migrate import upgrade
from estran.ontology import Ontology, load_ontology

DATABASE_URL = os.environ.get("ESTRAN_TEST_DATABASE_URL")


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if "integration" in Path(str(item.fspath)).parts:
            item.add_marker(pytest.mark.integration)
            if not DATABASE_URL:
                item.add_marker(pytest.mark.skip(reason="ESTRAN_TEST_DATABASE_URL is not set"))


@pytest.fixture(scope="session")
def database_url() -> str:
    assert DATABASE_URL
    return DATABASE_URL


@pytest.fixture(scope="session")
def migrated_engine(database_url: str) -> Iterator[Engine]:
    engine = create_db_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("DROP SCHEMA public CASCADE"))
        connection.execute(text("CREATE SCHEMA public"))
    upgrade(database_url)
    yield engine
    engine.dispose()


@pytest.fixture
def engine(migrated_engine: Engine) -> Engine:
    with migrated_engine.begin() as connection:
        connection.execute(
            text("TRUNCATE provenance, links, objects, runs, sources RESTART IDENTITY CASCADE")
        )
    return migrated_engine


@pytest.fixture(scope="session")
def ontology(ontology_path: Path) -> Ontology:
    return load_ontology(ontology_path)


@pytest.fixture
def snapshot_dir(tmp_path: Path, fixtures_dir: Path) -> Path:
    """A snapshot directory holding the 5-entry KEV sample under the name the manifest expects."""
    shutil.copy(fixtures_dir / "kev_sample.json", tmp_path / "kev.json")
    return tmp_path
