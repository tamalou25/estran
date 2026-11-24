"""Apply database migrations: `python -m estran.db.migrate` brings the schema up to date."""

from pathlib import Path

from alembic import command
from alembic.config import Config

MIGRATIONS = Path(__file__).parent / "migrations"


def _config(url: str) -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS))
    config.attributes["url"] = url
    return config


def upgrade(url: str, revision: str = "head") -> None:
    command.upgrade(_config(url), revision)


def downgrade(url: str, revision: str) -> None:
    command.downgrade(_config(url), revision)


if __name__ == "__main__":
    from estran.settings import get_settings

    upgrade(get_settings().database_url)
    print("database schema is up to date")  # noqa: T201
