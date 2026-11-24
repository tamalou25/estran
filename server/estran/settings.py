"""Runtime configuration, read from ESTRAN_* environment variables.

The database password is never an environment variable in the deployed stack: it is read from
a file (ESTRAN_DATABASE_PASSWORD_FILE) that only the service concerned can see.
"""

from pathlib import Path
from typing import Literal, Self

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import URL, make_url


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ESTRAN_")

    # Either a full address (tests, local development)...
    database_url: SecretStr | None = None
    # ...or its parts, with the password kept in a file.
    database_host: str | None = None
    database_port: int = 5432
    database_name: str | None = None
    database_user: str | None = None
    database_password_file: Path | None = None

    # Only for the migration job: where the passwords of the service roles are kept.
    role_passwords_dir: Path | None = None

    mode: Literal["live", "snapshot"] = "live"
    ontology_path: Path = Path("/app/ontology/ontology.yaml")
    snapshot_dir: Path = Path("/app/data/snapshot")
    heartbeat_file: Path = Path("/tmp/estran-collector.heartbeat")  # noqa: S108

    @model_validator(mode="after")
    def _database_is_configured(self) -> Self:
        parts = (
            self.database_host,
            self.database_name,
            self.database_user,
            self.database_password_file,
        )
        if self.database_url is None and not all(parts):
            raise ValueError(
                "set ESTRAN_DATABASE_URL, or ESTRAN_DATABASE_HOST, ESTRAN_DATABASE_NAME, "
                "ESTRAN_DATABASE_USER and ESTRAN_DATABASE_PASSWORD_FILE"
            )
        return self

    def db_url(self) -> URL:
        if self.database_url is not None:
            return make_url(self.database_url.get_secret_value())
        assert self.database_password_file is not None  # guaranteed by the validator
        return URL.create(
            "postgresql+psycopg",
            username=self.database_user,
            password=self.database_password_file.read_text(encoding="utf-8").strip(),
            host=self.database_host,
            port=self.database_port,
            database=self.database_name,
        )


def get_settings() -> Settings:
    return Settings()
