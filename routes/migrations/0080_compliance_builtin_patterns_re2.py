"""
Migration 0080: rewrite built-in compliance patterns for RE2.

Compliance ``regex_match`` rules now run through RE2 (``routes.user_regex``),
which has no lookarounds. Two built-in rules used a negative lookahead and
would report "Invalid regex" on every scan. This rewrites those two patterns,
where a stored profile still has them verbatim, to the RE2 forms shipped in
``routes.builtin_compliance_profiles``. Rules a user wrote are left alone;
the profile editor now rejects patterns RE2 cannot compile.

The patterns are copied here, not imported, so the migration keeps doing
the same thing if the built-in profiles change later.
"""

from __future__ import annotations

import json

VERSION = 80
DESCRIPTION = "Rewrite built-in compliance lookahead patterns for RE2"

_REWRITES = {
    r"switchport trunk native vlan\s+(?!1\b)\d+": r"switchport trunk native vlan\s+(?:[02-9]|1\d)\d*",
    r"hostname\s+(?!Router|Switch)\S+": (
        r"hostname\s+(?:[^\srs]\S*"
        r"|r(?:\b|[^\so]\S*|o(?:\b|[^\su]\S*|u(?:\b|[^\st]\S*|t(?:\b|[^\se]\S*|e(?:\b|[^\sr]\S*)))))"
        r"|s(?:\b|[^\sw]\S*|w(?:\b|[^\si]\S*|i(?:\b|[^\st]\S*|t(?:\b|[^\sc]\S*|c(?:\b|[^\sh]\S*))))))"
    ),
}


def _rewrite(rules_text: str) -> str | None:
    """The rules JSON with built-in lookahead patterns replaced, or None
    when nothing changes (or the stored value is not a JSON rule list)."""
    try:
        rules = json.loads(rules_text or "[]")
    except ValueError:
        return None
    if not isinstance(rules, list):
        return None
    changed = False
    for rule in rules:
        if isinstance(rule, dict) and rule.get("type") == "regex_match":
            new = _REWRITES.get(rule.get("pattern"))
            if new is not None:
                rule["pattern"] = new
                changed = True
    return json.dumps(rules) if changed else None


async def up(db) -> None:
    cursor = await db.execute("SELECT id, rules FROM compliance_profiles")
    for row in await cursor.fetchall():
        new_text = _rewrite(row[1])
        if new_text is not None:
            await db.execute("UPDATE compliance_profiles SET rules = ? WHERE id = ?", (new_text, row[0]))
    await db.commit()
