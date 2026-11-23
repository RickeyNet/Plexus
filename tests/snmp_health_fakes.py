"""A fake SNMP agent for the poll's state-based health checks
(netcontrol/snmp_health.py and the vendor tables on it), and the poll and
alert-evaluation harness their tests share. Invented rows only."""

from __future__ import annotations

import netcontrol.routes.state as state
import routes.database as db

# sysUpTime: a walk the poll makes before it asks for any health table.
SYS_UPTIME = "1.3.6.1.2.1.1.3"
NO_SUCH = "No Such Instance currently exists at this OID"


class Agent:
    """Answers walks and GETs from invented rows, and records each request.
    ``cut``: column OIDs whose walk is cut short (a timeout)."""

    def __init__(self, rows: dict, answers: dict | None = None, *, cut: set[str] | None = None, silent_gets=False):
        self.rows = rows
        self.answers = answers or {}
        self.cut = cut or set()
        self.silent_gets = silent_gets
        self.walks: list[str] = []
        self.gets: list[tuple[str, ...]] = []

    def _rows(self, oid: str) -> dict:
        return {k: v for k, v in self.rows.items() if k.startswith(oid + ".")}

    async def walk(self, oid: str) -> dict | None:
        """A source's walk: None for a walk cut short."""
        self.walks.append(oid)
        return None if oid in self.cut else self._rows(oid)

    async def walk_table(self, oid: str, cap: int | None = None) -> tuple[dict, bool]:
        """``cap``: a reader's own row cap (the walk stops there, cut short)."""
        self.walks.append(oid)
        rows = self._rows(oid)
        if cap is not None and len(rows) >= cap:
            return dict(list(rows.items())[:cap]), False
        return rows, oid not in self.cut

    async def get(self, oids: tuple[str, ...]) -> dict:
        self.gets.append(oids)
        if self.silent_gets:
            return {}
        return {oid: self.answers.get(oid, NO_SUCH) for oid in oids}

    def asked(self) -> set[str]:
        return {oid for oids in self.gets for oid in oids}


async def poll(monkeypatch, host: dict, agent: Agent) -> dict:
    """One whole monitoring poll of ``host`` against ``agent`` (SNMP only)."""
    import netcontrol.routes.monitoring as monitoring
    from netcontrol.routes.snmp import SNMP_TIMEOUT_ERROR

    async def _walk(_ip, _timeout, _cfg, oid, *_args, return_errors=False, engine=None, **_kwargs):
        rows, complete = await agent.walk_table(oid)
        if return_errors:
            return rows, (None if complete else SNMP_TIMEOUT_ERROR)
        return rows

    async def _get(_ip, _timeout, _cfg, oids, *, engine=None):
        return await agent.get(oids), None

    monkeypatch.setattr(monitoring, "PYSMNP_AVAILABLE", True)
    monkeypatch.setattr(monitoring, "_snmp_walk", _walk)
    monkeypatch.setattr(monitoring, "_snmp_get_values", _get)
    monkeypatch.setitem(state.MONITORING_CONFIG, "icmp_enabled", False)
    return await monitoring._poll_host_monitoring(host, None, {"enabled": True})


async def add_host(device_type: str, address: str = "192.0.2.90") -> tuple[int, int]:
    await db.init_db()
    group_id = await db.create_group("health-test")
    host_id = await db.add_host(group_id, "device-a", address, device_type)
    return group_id, host_id


def res(host_id: int, **states: dict | None) -> dict:
    """A poll result carrying the given check states (``power_supply_health=...``)."""
    out = {
        "host_id": host_id,
        "cpu_percent": None,
        "memory_percent": None,
        "if_down_count": 0,
        "if_details": [],
        "vpn_tunnels_down": 0,
        "vpn_details": [],
    }
    out.update({k: v for k, v in states.items() if v is not None})
    return out


async def evaluate(host_id: int, group_id: int, result: dict, rules: list | None = None, **kw) -> int:
    from netcontrol.routes.monitoring import _evaluate_alerts_for_poll

    poll_id = await db.create_monitoring_poll(host_id)
    return await _evaluate_alerts_for_poll(result, poll_id, group_id, rules or [], **kw)


async def open_alerts(host_id: int) -> dict[str, dict]:
    return {a["dedup_key"]: a for a in await db.get_monitoring_alerts(host_id, acknowledged=False)}
