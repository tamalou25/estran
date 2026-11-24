"""Runtime configuration, read from ESTRAN_* environment variables."""

from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ESTRAN_")

    database_url: str
    mode: Literal["live", "snapshot"] = "live"
    ontology_path: Path = Path("/app/ontology/ontology.yaml")
    snapshot_dir: Path = Path("/app/data/snapshot")
    heartbeat_file: Path = Path("/tmp/estran-collector.heartbeat")  # noqa: S108


def get_settings() -> Settings:
    return Settings()
