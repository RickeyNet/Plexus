"""The per-interface join of the monitoring poll's IF-MIB walks.

Each walked column is keyed by ifIndex once (``snmp.by_last_index``) instead
of scanning every column with ``oid.endswith("." + idx)`` per interface. The
old scan is kept here as the reference: both must give the same values,
including ``1`` against ``11`` and ``111``, a missing column, a bad value and
a repeated index. Invented rows only."""

from __future__ import annotations

import routes.database as db
from netcontrol.routes.snmp import by_last_index

from snmp_health_fakes import SYS_UPTIME, Agent, add_host, poll

IF_OPER = "1.3.6.1.2.1.2.2.1.8"
IF_ADMIN = "1.3.6.1.2.1.2.2.1.7"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"
IF_HC_IN = "1.3.6.1.2.1.31.1.1.1.6"
IF_HC_OUT = "1.3.6.1.2.1.31.1.1.1.10"
IF_IN_ERRORS = "1.3.6.1.2.1.2.2.1.14"
IF_OUT_ERRORS = "1.3.6.1.2.1.2.2.1.20"
IF_IN_DISCARDS = "1.3.6.1.2.1.2.2.1.13"
IF_OUT_DISCARDS = "1.3.6.1.2.1.2.2.1.19"


def _old_lookup(walk: dict, idx: str) -> int:
    """The scan the poll made before: first OID ending ``.idx``, 0 when none
    or when its value is not a number."""
    value = 0
    for oid, raw in walk.items():
        if oid.endswith("." + idx):
            try:
                value = int(raw)
            except (ValueError, TypeError):
                pass
            break
    return value


def _new_lookup(walk: dict, idx: str) -> int:
    table = by_last_index(walk)
    if idx not in table:
        return 0
    try:
        return int(table[idx])
    except (ValueError, TypeError):
        return 0


def test_by_last_index_matches_the_endswith_scan():
    walk = {
        f"{IF_HC_IN}.1": 10,
        f"{IF_HC_IN}.11": 110,
        f"{IF_HC_IN}.111": 1110,
        f"{IF_HC_IN}.2": "not-a-number",
        # Two OIDs ending in the same index (another table's row under the
        # column): the first one wins, as the scan's ``break`` did.
        f"{IF_HC_IN}.7.5": 75,
        f"{IF_HC_IN}.8.5": 85,
        "5": 999,  # no dot: never matched
        f"{IF_HC_IN}.": 1,  # empty index: never matched
    }
    for idx in ("1", "11", "111", "2", "5", "3", "1111"):
        assert _new_lookup(walk, idx) == _old_lookup(walk, idx), idx
    assert by_last_index(walk)["5"] == 75
    assert by_last_index(walk, first_wins=False)["5"] == 85
    assert "" not in by_last_index(walk)
    assert by_last_index({}) == {}


async def test_the_poll_gives_the_same_interface_rows_as_the_old_join(monkeypatch):
    group_id, host_id = await add_host("cisco_xe")
    rows: dict = {f"{SYS_UPTIME}.0": 4200}
    for idx, oper, admin in (("1", 1, 1), ("11", 2, 2), ("111", 2, 1)):
        rows[f"{IF_OPER}.{idx}"] = oper
        rows[f"{IF_ADMIN}.{idx}"] = admin
        rows[f"{IF_NAME}.{idx}"] = f"Gi0/{idx}"
    for idx in ("1", "11", "111"):
        n = int(idx)
        rows[f"{IF_HIGH_SPEED}.{idx}"] = 1000 + n
        rows[f"{IF_HC_IN}.{idx}"] = 10 * n
        rows[f"{IF_HC_OUT}.{idx}"] = 20 * n
    # Error counters for 1 and 11 only: the column is missing for 111.
    for idx in ("1", "11"):
        rows[f"{IF_IN_ERRORS}.{idx}"] = 3 * int(idx)
        rows[f"{IF_OUT_ERRORS}.{idx}"] = 4 * int(idx)
        rows[f"{IF_IN_DISCARDS}.{idx}"] = 5 * int(idx)
    rows[f"{IF_OUT_DISCARDS}.11"] = "bad"
    agent = Agent(rows)
    host = {**(await db.get_host(host_id)), "group_id": group_id}
    result = await poll(monkeypatch, host, agent)

    def column(oid: str) -> dict:
        return {k: v for k, v in rows.items() if k.startswith(oid + ".")}

    expected = []
    for idx in ("1", "11", "111"):
        oper, admin = rows[f"{IF_OPER}.{idx}"], rows[f"{IF_ADMIN}.{idx}"]
        expected.append(
            {
                "if_index": int(idx),
                "name": f"Gi0/{idx}",
                "status": "up" if oper == 1 else ("admin_down" if admin == 2 else "down"),
                "speed_mbps": _old_lookup(column(IF_HIGH_SPEED), idx),
                "in_octets": _old_lookup(column(IF_HC_IN), idx),
                "out_octets": _old_lookup(column(IF_HC_OUT), idx),
                "in_errors": _old_lookup(column(IF_IN_ERRORS), idx),
                "out_errors": _old_lookup(column(IF_OUT_ERRORS), idx),
                "in_discards": _old_lookup(column(IF_IN_DISCARDS), idx),
                "out_discards": _old_lookup(column(IF_OUT_DISCARDS), idx),
            }
        )
    assert sorted(result["if_details"], key=lambda d: d["if_index"]) == expected
    assert expected[0]["in_octets"] == 10 and expected[2]["in_errors"] == 0
    assert expected[1]["out_discards"] == 0
    assert (result["if_up_count"], result["if_admin_down"], result["if_down_count"]) == (1, 1, 1)
