"""Least privilege in the database: the API can only read, the collector cannot destroy."""

import pytest
from sqlalchemy import Engine, make_url, text
from sqlalchemy.exc import OperationalError, ProgrammingError

from estran.collector.connectors.kev import KevConnector
from estran.collector.runner import run_connector
from estran.db.engine import create_db_engine
from estran.db.roles import sync_roles

PASSWORDS = {"estran_collector": "collector-test-password", "estran_api": "api-test-password"}


def engine_as(database_url: str, role: str, password: str) -> Engine:
    return create_db_engine(make_url(database_url).set(username=role, password=password))


@pytest.fixture
def roles(engine) -> None:
    with engine.begin() as connection:
        sync_roles(connection, PASSWORDS)


@pytest.fixture
def api_engine(roles, database_url):
    engine = engine_as(database_url, "estran_api", PASSWORDS["estran_api"])
    yield engine
    engine.dispose()


@pytest.fixture
def collector_engine(roles, database_url):
    engine = engine_as(database_url, "estran_collector", PASSWORDS["estran_collector"])
    yield engine
    engine.dispose()


def refused(engine: Engine, sql: str) -> bool:
    try:
        with engine.begin() as connection:
            connection.execute(text(sql))
    except ProgrammingError as error:
        return "permission denied" in str(error) or "must be owner" in str(error)
    return False


# --- the API role ---------------------------------------------------------------------------


def test_api_role_can_read_everything_the_api_serves(api_engine, engine, ontology, snapshot_dir):
    run_connector(engine, ontology, KevConnector(), mode="snapshot", snapshot_dir=snapshot_dir)

    with api_engine.connect() as connection:
        for table in ("sources", "runs", "objects", "links", "provenance"):
            assert connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one() > 0


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT INTO objects (type, key, title) VALUES ('vendor', 'x', 'X')",
        "UPDATE objects SET title = 'hacked'",
        "DELETE FROM objects",
        "TRUNCATE objects CASCADE",
        "DROP TABLE objects CASCADE",
        "CREATE TABLE loot (id int)",
        "ALTER TABLE objects ADD COLUMN extra text",
        "UPDATE sources SET licence = 'forged'",
    ],
)
def test_api_role_cannot_change_anything(api_engine, sql):
    assert refused(api_engine, sql)


# --- the collector role ---------------------------------------------------------------------


def test_collector_role_can_run_a_full_collection(collector_engine, ontology, snapshot_dir):
    result = run_connector(
        collector_engine, ontology, KevConnector(), mode="snapshot", snapshot_dir=snapshot_dir
    )

    assert result.status == "success"
    assert result.objects == 12


def test_collector_role_can_run_twice(collector_engine, ontology, snapshot_dir):
    connector = KevConnector()
    run_connector(collector_engine, ontology, connector, mode="snapshot", snapshot_dir=snapshot_dir)

    second = run_connector(
        collector_engine, ontology, connector, mode="snapshot", snapshot_dir=snapshot_dir
    )

    assert second.status == "unchanged"


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM objects",
        "TRUNCATE objects CASCADE",
        "DROP TABLE objects CASCADE",
        "CREATE TABLE loot (id int)",
        "ALTER TABLE objects ADD COLUMN extra text",
    ],
)
def test_collector_role_cannot_destroy_or_reshape_the_store(collector_engine, sql):
    assert refused(collector_engine, sql)


# --- the roles themselves -------------------------------------------------------------------


def test_service_roles_have_no_administrative_power(engine, roles):
    with engine.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolreplication, "
                "rolbypassrls "
                "FROM pg_roles WHERE rolname IN ('estran_collector', 'estran_api')"
            )
        ).all()

    assert sorted(row.rolname for row in rows) == ["estran_api", "estran_collector"]
    assert all(not any(row[1:]) for row in rows)


def test_wrong_password_is_refused(roles, database_url):
    engine = engine_as(database_url, "estran_api", "not-the-password")

    with pytest.raises(OperationalError, match="password authentication failed"):
        engine.connect()


def test_syncing_again_rotates_the_passwords(engine, roles, database_url):
    with engine.begin() as connection:
        sync_roles(connection, {**PASSWORDS, "estran_api": "rotated-password"})

    with pytest.raises(OperationalError):
        engine_as(database_url, "estran_api", PASSWORDS["estran_api"]).connect()
    with engine_as(database_url, "estran_api", "rotated-password").connect() as connection:
        assert connection.execute(text("SELECT 1")).scalar_one() == 1


def test_password_with_quotes_cannot_break_out_of_the_statement(engine, database_url):
    hostile = "x'; DROP TABLE objects; --"
    with engine.begin() as connection:
        sync_roles(connection, {**PASSWORDS, "estran_api": hostile})

    with engine_as(database_url, "estran_api", hostile).connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM objects")).scalar_one() == 0


def test_unknown_role_name_is_rejected(engine):
    with pytest.raises(ValueError, match="estran_admin"), engine.begin() as connection:
        sync_roles(connection, {"estran_admin": "x"})
