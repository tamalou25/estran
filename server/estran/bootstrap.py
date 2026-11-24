"""Create the database passwords on first start: `python -m estran.bootstrap <directory>`.

Each installation gets its own random passwords, so nothing secret is ever written in the
repository or typed by hand. One sub-directory per role lets each container mount only the
password it needs:

    <directory>/owner/password       database owner (migrations only)
    <directory>/collector/password   role that writes collected data
    <directory>/api/password         role that can only read

Nothing here is readable by "everyone". Files belong to the user and group running this
program; the database container, which runs under another user, is given that group (see
`group_add` in compose.yaml).
"""

import os
import secrets
import sys
from pathlib import Path

SECRET_NAMES = ("owner", "collector", "api")
TOKEN_BYTES = 32  # 256 bits of randomness, 43 URL-safe characters

DIRECTORY_MODE = 0o750  # owner: all, group: read and enter, others: nothing
FILE_MODE = 0o440  # owner and group: read, others: nothing


def ensure_secrets(directory: Path) -> list[str]:
    """Create the missing passwords and return their names. Existing ones are never changed.

    Permissions are (re)applied on every run, which also repairs an installation whose
    files were created with wider rights.
    """
    created = []
    directory.chmod(DIRECTORY_MODE)
    for name in SECRET_NAMES:
        folder = directory / name
        folder.mkdir(mode=DIRECTORY_MODE, exist_ok=True)
        folder.chmod(DIRECTORY_MODE)  # mkdir's mode is subject to the umask
        target = folder / "password"
        if target.exists() and target.stat().st_size > 0:
            target.chmod(FILE_MODE)
            continue
        _write_new(target, secrets.token_urlsafe(TOKEN_BYTES))
        created.append(name)
    return created


def _write_new(target: Path, password: str) -> None:
    """Write aside then rename: a reader never sees a half-written password.

    The file is created with its final, restricted permissions (and fails if something is
    already there), so the password never exists on disk readable by anyone else.
    """
    temporary = target.with_suffix(".tmp")
    temporary.unlink(missing_ok=True)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE)
    try:
        os.write(descriptor, password.encode("utf-8"))
    finally:
        os.close(descriptor)
    os.replace(temporary, target)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python -m estran.bootstrap <directory>")
    new = ensure_secrets(Path(sys.argv[1]))
    print(f"secrets: {len(new)} created, {len(SECRET_NAMES) - len(new)} kept")  # noqa: T201
