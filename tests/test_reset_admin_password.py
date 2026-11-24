"""``scripts/reset_admin_password.py`` shows a password only when it made
one up: a password the operator supplied is not repeated on the terminal."""

from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path

import pytest
import routes.database as db

REPO_ROOT = Path(__file__).resolve().parent.parent

_spec = importlib.util.spec_from_file_location(
    "reset_admin_password", REPO_ROOT / "scripts" / "reset_admin_password.py"
)
assert _spec is not None and _spec.loader is not None
reset = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(reset)

SUPPLIED = "Supplied-Example-Pass-1"


@pytest.fixture(autouse=True)
def _no_env_password(monkeypatch):
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-reset-script")
    monkeypatch.delenv("PLEXUS_DEFAULT_ADMIN_PASSWORD", raising=False)


def _password_lines(out: str) -> list[str]:
    return [line for line in out.splitlines() if line.startswith("[ok] password:")]


def test_a_password_given_on_the_command_line_is_not_printed(capsys):
    assert asyncio.run(reset._run("admin", SUPPLIED)) == 0

    out = capsys.readouterr().out
    assert SUPPLIED not in out
    assert _password_lines(out) == ["[ok] password: as supplied (--password); not shown"]


def test_a_password_from_the_environment_is_not_printed(monkeypatch, capsys):
    monkeypatch.setenv("PLEXUS_DEFAULT_ADMIN_PASSWORD", SUPPLIED)

    assert asyncio.run(reset._run("admin", None)) == 0

    out = capsys.readouterr().out
    assert SUPPLIED not in out
    assert _password_lines(out) == ["[ok] password: as supplied (PLEXUS_DEFAULT_ADMIN_PASSWORD); not shown"]


def test_a_generated_password_is_printed_once_and_signs_the_account_in(capsys):
    assert asyncio.run(reset._run("admin", None)) == 0

    lines = _password_lines(capsys.readouterr().out)
    assert len(lines) == 1
    shown = lines[0].removeprefix("[ok] password:").strip()
    assert len(shown) >= 16

    async def _stored():
        return await db.get_user_by_username("admin")

    user = asyncio.run(_stored())
    assert user["role"] == "admin"
    assert reset._hash_password(shown, user["salt"]) == user["password_hash"]
