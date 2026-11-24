"""Reset or create a local admin account for Plexus.

Usage (from repo root):
    python scripts/reset_admin_password.py --username admin --password "TempPass123!"

If --password is omitted, PLEXUS_DEFAULT_ADMIN_PASSWORD is used when set,
else a random password; either way it is printed once.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import os
import secrets
import sys

# Ensure project root is importable when script is run directly.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import routes.database as db


def _hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        f"{salt}:".encode(),
        600_000,
        dklen=64,
    ).hex()


def _sanitize_username(raw: str) -> str:
    value = (raw or "admin").strip()
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    cleaned = "".join(ch for ch in value if ch in allowed).strip("._-")
    return cleaned or "admin"


async def _run(username: str, password: str | None) -> int:
    await db.init_db()

    username = _sanitize_username(username)
    if not password:
        # No shared fallback: a fixed default would let anyone who knows it
        # sign in as admin until the operator changes it.
        password = os.getenv("PLEXUS_DEFAULT_ADMIN_PASSWORD", "").strip() or secrets.token_urlsafe(16)

    salt = secrets.token_hex(16)
    pw_hash = _hash_password(password, salt)

    users = await db.get_all_users()
    admins = [u for u in users if (u.get("role") or "").lower() == "admin"]

    user = await db.get_user_by_username(username)
    if user:
        await db.update_user_admin(int(user["id"]), role="admin")
        await db.update_user_password(int(user["id"]), pw_hash, salt, must_change_password=False)
        # A local password signs in a local account only: an account an
        # external provider managed becomes local here (and loses its bound
        # SSO subject), or the new password would never be accepted.
        was_managed = str(user.get("auth_provider") or "")
        if was_managed:
            await db.set_user_auth_provider(int(user["id"]), "", clear_external_id=True)
            print(f"[info] the account was managed by {was_managed}; it is now a local account")
        # End the sessions signed in with the old password.
        await db.bump_user_session_epoch(int(user["id"]))
        action = "updated existing user"
    else:
        await db.create_user(
            username,
            pw_hash,
            salt,
            display_name="Administrator",
            role="admin",
            must_change_password=False,
        )
        action = "created new admin user"

    print("[ok]", action)
    print("[ok] username:", username)
    # codeql[py/clear-text-logging-sensitive-data]: break-glass CLI run by an
    # operator on the host. The whole point is to display the new password so
    # the operator can use it for first login. Output goes to the operator's
    # terminal, not to a log file.
    print("[ok] password:", password)
    print("[ok] must_change_password: false")
    print("[info] admins_before:", len(admins))

    # Helpful auth-provider hint: local admin break-glass is enabled by default,
    # but show current provider state when available.
    if hasattr(db, "get_auth_setting"):
        try:
            auth_cfg = await db.get_auth_setting("auth_config")
            if isinstance(auth_cfg, dict):
                provider = str(auth_cfg.get("provider") or "local")
                print("[info] auth_provider:", provider)
                if provider != "local":
                    print("[hint] Provider is not local. Break-glass local admin login is enabled by default")
                    print("[hint] via PLEXUS_BREAKGLASS_LOCAL_ADMIN=true.")
        except Exception:
            pass

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Reset/create Plexus local admin account")
    parser.add_argument("--username", default=os.getenv("PLEXUS_INITIAL_ADMIN_USERNAME", "admin"))
    parser.add_argument("--password", default=None)
    args = parser.parse_args()
    return asyncio.run(_run(args.username, args.password))


if __name__ == "__main__":
    raise SystemExit(main())
