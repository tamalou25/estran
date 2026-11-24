"""Least privilege in the database.

Three identities use the store, each with only the rights its job needs:

    owner             creates the schema (migrations). Used by the migration job only.
    estran_collector  reads, inserts and updates collected data. Cannot delete or reshape.
    estran_api        reads. Nothing else.

`sync_roles` is idempotent and runs at every start: it also realigns the passwords, so
replacing the secrets and restarting is all a rotation takes.
"""

from pathlib import Path

from psycopg import sql
from sqlalchemy import Connection, text

TABLES = ("sources", "runs", "objects", "links", "provenance")

PRIVILEGES: dict[str, tuple[str, ...]] = {
    "estran_collector": ("SELECT", "INSERT", "UPDATE"),
    "estran_api": ("SELECT",),
}

# Name of each role's password inside the secrets directory (see estran.bootstrap).
SECRET_OF_ROLE = {"estran_collector": "collector", "estran_api": "api"}


def read_passwords(directory: Path) -> dict[str, str]:
    return {
        role: (directory / name / "password").read_text(encoding="utf-8").strip()
        for role, name in SECRET_OF_ROLE.items()
    }


def sync_roles(connection: Connection, passwords: dict[str, str]) -> None:
    """Create or update the service roles. Must run as the database owner, after migrations."""
    unknown = set(passwords) - PRIVILEGES.keys()
    if unknown:
        raise ValueError(f"unknown role(s): {', '.join(sorted(unknown))}")

    database = connection.execute(text("SELECT current_database()")).scalar_one()
    # Nobody gets anything by default: every right below is granted by name.
    _run(connection, "REVOKE ALL ON DATABASE {} FROM PUBLIC", sql.Identifier(database))
    _run(connection, "REVOKE ALL ON SCHEMA public FROM PUBLIC")

    for role, password in passwords.items():
        name = sql.Identifier(role)
        exists = connection.execute(
            text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role}
        ).first()
        # A password cannot be a bound parameter in CREATE/ALTER ROLE: it is quoted as an
        # SQL literal by the driver, never concatenated by hand.
        _run(
            connection,
            ("ALTER" if exists else "CREATE")
            + " ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
            + " PASSWORD {}",
            name,
            sql.Literal(password),
        )
        _run(connection, "GRANT CONNECT ON DATABASE {} TO {}", sql.Identifier(database), name)
        _run(connection, "GRANT USAGE ON SCHEMA public TO {}", name)
        _run(connection, "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {}", name)
        _run(
            connection,
            "GRANT {} ON {} TO {}",
            sql.SQL(", ").join(sql.SQL(privilege) for privilege in PRIVILEGES[role]),
            sql.SQL(", ").join(sql.Identifier(table) for table in TABLES),
            name,
        )


def _run(connection: Connection, statement: str, *parts: sql.Composable) -> None:
    driver_connection = connection.connection.driver_connection
    connection.exec_driver_sql(sql.SQL(statement).format(*parts).as_string(driver_connection))
