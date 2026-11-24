import pytest
from pydantic import ValidationError

from estran.settings import Settings


def test_database_address_is_built_from_parts_and_a_password_file(tmp_path, monkeypatch):
    secret = tmp_path / "password"
    secret.write_text("s3cr3t-token\n", encoding="utf-8")
    monkeypatch.setenv("ESTRAN_DATABASE_HOST", "db")
    monkeypatch.setenv("ESTRAN_DATABASE_NAME", "estran")
    monkeypatch.setenv("ESTRAN_DATABASE_USER", "estran_api")
    monkeypatch.setenv("ESTRAN_DATABASE_PASSWORD_FILE", str(secret))

    url = Settings().db_url()

    assert (url.drivername, url.host, url.port, url.database) == (
        "postgresql+psycopg",
        "db",
        5432,
        "estran",
    )
    assert url.username == "estran_api"
    assert url.password == "s3cr3t-token"


def test_password_with_special_characters_survives_intact(tmp_path, monkeypatch):
    secret = tmp_path / "password"
    secret.write_text("p@ss:/w#rd?&%", encoding="utf-8")
    monkeypatch.setenv("ESTRAN_DATABASE_HOST", "db")
    monkeypatch.setenv("ESTRAN_DATABASE_NAME", "estran")
    monkeypatch.setenv("ESTRAN_DATABASE_USER", "estran")
    monkeypatch.setenv("ESTRAN_DATABASE_PASSWORD_FILE", str(secret))

    assert Settings().db_url().password == "p@ss:/w#rd?&%"


def test_a_full_address_can_still_be_given_directly(monkeypatch):
    monkeypatch.setenv("ESTRAN_DATABASE_URL", "postgresql+psycopg://u:p@localhost:5433/x")

    url = Settings().db_url()

    assert (url.host, url.port, url.database, url.username) == ("localhost", 5433, "x", "u")


def test_password_never_appears_when_settings_are_printed(tmp_path, monkeypatch):
    secret = tmp_path / "password"
    secret.write_text("s3cr3t-token", encoding="utf-8")
    monkeypatch.setenv("ESTRAN_DATABASE_HOST", "db")
    monkeypatch.setenv("ESTRAN_DATABASE_NAME", "estran")
    monkeypatch.setenv("ESTRAN_DATABASE_USER", "estran")
    monkeypatch.setenv("ESTRAN_DATABASE_PASSWORD_FILE", str(secret))

    settings = Settings()

    assert "s3cr3t-token" not in repr(settings)
    assert "s3cr3t-token" not in str(settings.db_url())


def test_missing_database_configuration_is_reported(monkeypatch):
    for name in ("URL", "HOST", "NAME", "USER", "PASSWORD_FILE"):
        monkeypatch.delenv(f"ESTRAN_DATABASE_{name}", raising=False)

    with pytest.raises(ValidationError, match="ESTRAN_DATABASE"):
        Settings()


def test_unreadable_password_file_is_reported(tmp_path, monkeypatch):
    monkeypatch.setenv("ESTRAN_DATABASE_HOST", "db")
    monkeypatch.setenv("ESTRAN_DATABASE_NAME", "estran")
    monkeypatch.setenv("ESTRAN_DATABASE_USER", "estran")
    monkeypatch.setenv("ESTRAN_DATABASE_PASSWORD_FILE", str(tmp_path / "absent"))

    with pytest.raises(OSError, match="absent"):
        Settings().db_url()
