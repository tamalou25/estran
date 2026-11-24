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
