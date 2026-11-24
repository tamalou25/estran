import os
import stat
import sys

import pytest

from estran.bootstrap import SECRET_NAMES, ensure_secrets


def read(directory, name) -> str:
    return (directory / name / "password").read_text(encoding="utf-8")


def test_one_password_is_created_per_database_role(tmp_path):
    ensure_secrets(tmp_path)

    assert set(SECRET_NAMES) == {"owner", "collector", "api"}
    passwords = [read(tmp_path, name) for name in SECRET_NAMES]
    assert all(len(p) >= 32 for p in passwords)
    assert len(set(passwords)) == 3


def test_each_installation_gets_its_own_passwords(tmp_path):
    first, second = tmp_path / "a", tmp_path / "b"
    first.mkdir()
    second.mkdir()

    ensure_secrets(first)
    ensure_secrets(second)

    assert read(first, "owner") != read(second, "owner")


def test_existing_passwords_are_kept_on_restart(tmp_path):
    ensure_secrets(tmp_path)
    before = {name: read(tmp_path, name) for name in SECRET_NAMES}

    created = ensure_secrets(tmp_path)

    assert {name: read(tmp_path, name) for name in SECRET_NAMES} == before
    assert created == []


def test_a_missing_password_is_recreated_without_touching_the_others(tmp_path):
    ensure_secrets(tmp_path)
    owner = read(tmp_path, "owner")
    lost = tmp_path / "api" / "password"
    lost.chmod(0o644)  # Windows refuses to delete a read-only file
    lost.unlink()

    created = ensure_secrets(tmp_path)

    assert created == ["api"]
    assert read(tmp_path, "owner") == owner
    assert len(read(tmp_path, "api")) >= 32


def test_passwords_hold_only_characters_safe_in_any_context(tmp_path):
    ensure_secrets(tmp_path)

    for name in SECRET_NAMES:
        password = read(tmp_path, name)
        assert password.replace("-", "").replace("_", "").isalnum()
        assert password == password.strip()


# --- permissions: readable by the owner and one group, never by everyone ---------------------

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")


def mode(path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@posix_only
def test_passwords_are_not_readable_by_everyone(tmp_path):
    ensure_secrets(tmp_path)

    for name in SECRET_NAMES:
        assert mode(tmp_path / name / "password") == 0o440
        assert mode(tmp_path / name) == 0o750
    assert mode(tmp_path) == 0o750


@posix_only
def test_permissions_left_too_open_by_an_older_version_are_tightened(tmp_path):
    ensure_secrets(tmp_path)
    tmp_path.chmod(0o755)
    (tmp_path / "api").chmod(0o755)
    (tmp_path / "api" / "password").chmod(0o444)
    before = read(tmp_path, "api")

    created = ensure_secrets(tmp_path)

    assert created == []
    assert read(tmp_path, "api") == before
    assert mode(tmp_path / "api" / "password") == 0o440
    assert mode(tmp_path / "api") == 0o750
    assert mode(tmp_path) == 0o750


@posix_only
def test_password_is_never_on_disk_with_wider_permissions(tmp_path, monkeypatch):
    """The file must be created restricted, not created open and restricted afterwards."""
    seen: list[int] = []
    real_open = os.open

    def spying_open(path, flags, mode=0o777, **kwargs):
        if str(path).endswith(".tmp"):
            seen.append(mode)
            assert flags & os.O_EXCL
        return real_open(path, flags, mode, **kwargs)

    monkeypatch.setattr(os, "open", spying_open)
    old_umask = os.umask(0)  # the most permissive environment possible
    try:
        ensure_secrets(tmp_path)
    finally:
        os.umask(old_umask)

    assert seen == [0o440, 0o440, 0o440]
