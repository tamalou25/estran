"""Bring the database up to date: `python -m estran.db.migrate`.

Applies the schema migrations, then (when ESTRAN_ROLE_PASSWORDS_DIR is set) creates or
realigns the restricted roles used by the API and the collector.
"""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import URL

MIGRATIONS = Path(__file__).parent / "migrations"


def _config(url: str | URL) -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS))
    config.attributes["url"] = url
    return config


def upgrade(url: str | URL, revision: str = "head") -> None:
    command.upgrade(_config(url), revision)


def downgrade(url: str | URL, revision: str) -> None:
    command.downgrade(_config(url), revision)


if __name__ == "__main__":
    from estran.db.engine import create_db_engine
    from estran.db.roles import read_passwords, sync_roles
    from estran.settings import get_settings

    settings = get_settings()
    upgrade(settings.db_url())
    print("database schema is up to date")  # noqa: T201
    if settings.role_passwords_dir is not None:
        engine = create_db_engine(settings.db_url())
        with engine.begin() as connection:
            sync_roles(connection, read_passwords(settings.role_passwords_dir))
        engine.dispose()
        print("service roles are in place")  # noqa: T201
