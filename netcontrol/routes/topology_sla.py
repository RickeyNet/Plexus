"""SLA targets of topology (API-collected) entities.

An SLA target with a ``provider`` (``sla_targets.provider``, migration 0091)
applies to the entities the topology availability tracker follows for that
provider, narrowed by ``org_ref`` (one source), ``entity_type`` (``uplink``,
``tunnel``...) and ``entity_id`` when they are set, instead of inventory
hosts. ``evaluate_topology_sla_targets`` runs in the scheduled SLA pass
(``netcontrol.routes.monitoring.run_sla_cycle``), right after the host
targets, with the same metrics and the same met / warn / breach rule
(``classify_sla_value``):

  - ``uptime``: the time-weighted uptime % of the entity over the window
    (``get_topology_availability_summary``: degraded counts as available,
    unknown time is left out);
  - ``latency``, ``jitter``, ``packet_loss``: the mean of what the vendor
    reported for the entity over the window, from the raw samples and the
    daily rollups (``get_topology_entity_metric_values``). Only entities
    whose vendor reports the measurement have data (an OPNsense gateway
    today: dpinger RTT, RTT deviation as jitter, loss); every other entity
    is ``no_data``.

The result of every (target, entity) is stored with a history of changes
(``topology_sla_target_status``). A status that gets worse than it was
(to ``warn``, or to ``breach``) raises an alert the way the availability
tracker does (``deliver_alert``): a monitoring alert on the entity's
inventory host when it has one, else the notification channels. A muted
entity (``topology_mutes``) is evaluated and stored but raises nothing.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import routes.database as db

from netcontrol.routes.monitoring import (
    _SLA_VALUE_KEYS,
    _SLA_WINDOW_DAYS_MAX,
    _sla_alert_message,
    classify_sla_value,
)
from netcontrol.routes.topology_availability import (
    PROVIDER_LABELS,
    TYPE_LABELS,
    _mute_index,
    deliver_alert,
)
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.topology_sla")

ALERT_TYPE = "sla_breach"
_FMT = "%Y-%m-%d %H:%M:%S"
_RANK = {"no_data": 0, "met": 0, "warn": 1, "breach": 2}


def is_topology_target(target: dict) -> bool:
    """A target of topology entities (it names a provider), not of hosts."""
    return bool(str(target.get("provider") or "").strip())


def dedup_key(res: dict) -> str:
    return f"sla:topo:{res['target_id']}:{res['provider']}:{res['org_ref']}:{res['entity_type']}:{res['entity_id']}"


def _key(row: dict) -> tuple[str, int, str, str]:
    return (str(row["provider"]), int(row["org_ref"]), str(row["entity_type"]), str(row["entity_id"]))


def _window_days(target: dict) -> int:
    return max(1, min(_SLA_WINDOW_DAYS_MAX, int(target.get("window_days") or 30)))


def _sample_count(metric: str, values: dict | None) -> int:
    """How many samples the value is the mean of (uptime is time-weighted:
    no sample count)."""
    if not values or metric == "uptime":
        return 0
    return int(
        values.get({"latency": "latency_samples", "jitter": "jitter_samples"}.get(metric, "packet_loss_samples")) or 0
    )


async def _entities(target: dict) -> list[dict]:
    org_ref = target.get("org_ref")
    return await db.list_topology_entity_states(
        str(target["provider"]),
        int(org_ref) if org_ref is not None else None,
        str(target.get("entity_type") or "") or None,
        entity_id=str(target.get("entity_id") or "") or None,
    )


async def evaluate_topology_sla_targets(targets: list[dict], now: datetime | None = None) -> dict[str, Any]:
    """Evaluate every enabled topology target of ``targets`` for every
    entity it applies to, store the results and alert on a status that got
    worse. Returns the counts like ``evaluate_sla_targets``."""
    targets = [t for t in targets if t.get("enabled") and is_topology_target(t) and t.get("metric") in _SLA_VALUE_KEYS]
    evaluated_at = datetime.now(UTC).strftime(_FMT)
    now_text = (now if now.tzinfo else now.replace(tzinfo=UTC)).astimezone(UTC).strftime(_FMT) if now else None
    windows: dict[tuple[bool, int], tuple[dict, dict]] = {}
    results: list[dict] = []
    rows: dict[tuple, dict] = {}
    by_target = {int(t["id"]): t for t in targets}

    async def window_values(uptime: bool, days: int) -> tuple[dict, dict]:
        """The window and the values per entity key, read once per kind and length."""
        if (uptime, days) not in windows:
            if uptime:
                summary = await db.get_topology_availability_summary(days=days, now=now_text)
                windows[(uptime, days)] = (summary, {_key(e): e for e in summary["entities"]})
            else:
                found = await db.get_topology_entity_metric_values(days, now=now_text)
                windows[(uptime, days)] = (found, found["entities"])
        return windows[(uptime, days)]

    for target in targets:
        metric = str(target["metric"])
        window_days = _window_days(target)
        window, values_of = await window_values(metric == "uptime", window_days)
        for row in await _entities(target):
            key = _key(row)
            rows[key] = row
            values = values_of.get(key)
            value = values.get(_SLA_VALUE_KEYS[metric]) if values else None
            results.append(
                {
                    "target_id": int(target["id"]),
                    "provider": key[0],
                    "org_ref": key[1],
                    "entity_type": key[2],
                    "entity_id": key[3],
                    "name": str(row.get("name") or key[3]),
                    "site": str(row.get("site") or ""),
                    "metric": metric,
                    "value": value,
                    "target_value": target["target_value"],
                    "warning_value": target["warning_value"],
                    "status": classify_sla_value(
                        metric, value, float(target["target_value"]), float(target["warning_value"])
                    ),
                    "sample_count": _sample_count(metric, values),
                    "window_days": window_days,
                    "window_start": window["window_start"],
                    "window_end": window["window_end"],
                }
            )

    recorded = await db.record_topology_sla_target_statuses(results, evaluated_at)

    alerts = muted = 0
    worse = [
        r
        for r in recorded
        if r["status"] in ("warn", "breach")
        and r["value"] is not None
        and _RANK[r["status"]] > _RANK.get(r["previous_status"], 0)
    ]
    index = await _mute_index() if worse else None
    for res in worse:
        row = rows.get(_key(res)) or {}
        if index and row and index.match(row):
            muted += 1
            continue
        target = by_target[int(res["target_id"])]
        where = PROVIDER_LABELS.get(res["provider"], res["provider"])
        if row.get("org_name"):
            where = f"{where} {row['org_name']}"
        subject = f"{TYPE_LABELS.get(res['entity_type'], res['entity_type'])} {res['name']} ({where})"
        try:
            await deliver_alert(
                host_id=row.get("host_id"),
                name=res["name"],
                alert_type=ALERT_TYPE,
                metric=f"sla_{res['metric']}",
                message=f"{subject}: {_sla_alert_message(target, res['status'], res['value'], res['window_days'])}",
                severity="critical" if res["status"] == "breach" else "warning",
                dedup_key=dedup_key(res),
                value=res["value"],
                threshold=target["warning_value"] if res["status"] == "breach" else target["target_value"],
            )
            alerts += 1
        except Exception as exc:  # noqa: BLE001 - one failed alert must not stop the pass
            LOGGER.warning("topology sla: alert %s failed: %s", dedup_key(res), type(exc).__name__)

    counts = {"met": 0, "warn": 0, "breach": 0, "no_data": 0}
    for res in results:
        counts[res["status"]] += 1
    return {
        "targets": len(targets),
        "evaluated": len(results),
        **counts,
        "alerts": alerts,
        "muted": muted,
        "evaluated_at": evaluated_at,
    }
