"""Create the database passwords on first start: `python -m estran.bootstrap <directory>`.

Each installation gets its own random passwords, so nothing secret is ever written in the
repository or typed by hand. One sub-directory per role lets each container mount only the
password it needs:

    <directory>/owner/password       database owner (migrations only)
    <directory>/collector/password   role that writes collected data
    <directory>/api/password         role that can only read
"""

import os
import secrets
import sys
from pathlib import Path

SECRET_NAMES = ("owner", "collector", "api")
TOKEN_BYTES = 32  # 256 bits of randomness, 43 URL-safe characters


def ensure_secrets(directory: Path) -> list[str]:
    """Create the missing passwords and return their names. Existing ones are never changed."""
    created = []
    for name in SECRET_NAMES:
        target = directory / name / "password"
        if target.exists() and target.stat().st_size > 0:
            continue
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        # Written aside then renamed: a reader never sees a half-written password.
        temporary = target.with_suffix(".tmp")
        temporary.write_text(secrets.token_urlsafe(TOKEN_BYTES), encoding="utf-8")
        # Read-only for everyone *inside the mount*: isolation comes from each container
        # mounting only its own sub-directory, and containers run under different users.
        temporary.chmod(0o444)
        os.replace(temporary, target)
        created.append(name)
    return created


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python -m estran.bootstrap <directory>")
    new = ensure_secrets(Path(sys.argv[1]))
    print(f"secrets: {len(new)} created, {len(SECRET_NAMES) - len(new)} kept")  # noqa: T201
