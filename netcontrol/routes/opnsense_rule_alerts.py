"""
opnsense_rule_alerts.py -- Alerts on risky filter rule changes of an OPNsense firewall.

Called by the OPNsense collection (``opnsense_collection.store_config_backup``)
right after it stored a NEW config backup of the firewall's inventory host
(an unchanged ``config.xml`` writes no row and calls nothing here). The new
``config.xml`` and the host's previous successful backup are parsed
(``netcontrol.integrations.pathtrace.opnsense_config.parse_document``) and
compared (``netcontrol.integrations.opnsense.rules.rule_change_findings``):

  - **Raised.** One alert per rule that became any-to-any (a new pass rule
    from any to any, or one widened or enabled) or shadowed (a new rule
    covered on arrival, or one a new, moved or widened rule now covers).
    A monitoring alert on the firewall's inventory host, through the path
    the certificate expiry alerts use
    (``topology_availability.deliver_alert``: listed under Alerts, handed
    to the notification channels when new). Dedup key
    ``opnsense-rule:<host_id>:<kind>:<rule key>``, so the same finding is
    never open twice. Severity: ``warning`` for an any-to-any rule and for
    a rule shadowed by one that does the opposite (``conflicting``: traffic
    is decided differently from what the rule says), ``info`` for a
    redundant shadow (the covering rule does the same: nothing changes for
    traffic). Configuration posture findings elsewhere (the Cato egress
    check) are warnings too; ``critical`` stays for outages and expired
    certificates. At most ``MAX_ALERTS_PER_BACKUP`` per backup.
  - **Resolved.** A finding the next new backup no longer has (the rule was
    removed, narrowed, disabled or moved back) has its open alert
    acknowledged as ``auto-resolved``.
  - **Not raised.** The first backup of a host (nothing to compare with),
    an unchanged configuration (no new backup), a finding the previous
    backup already had, and a backup that is no OPNsense ``config.xml``.
    A mute of the source's firewall (or its site) in the topology
    availability tracker (``security_events.source_muted``) and a
    monitoring suppression of the host (all metrics or the finding's
    metric, ``opnsense_rule_any_any`` / ``opnsense_rule_shadowed``;
    ``security_events.host_suppressed``) keep them from being raised, as
    for the firewall's IDS alerts.

The message holds parsed rule fields only (number, interfaces, action,
source, destination, description, the covering rule), never backup text or
alias contents. The comparison runs in a worker thread. Best effort: a failure is logged by the caller and the
collection is stored anyway.
"""

from __future__ import annotations

import asyncio
from typing import Any

import routes.database as db

from netcontrol.integrations.opnsense.rules import rule_change_findings
from netcontrol.integrations.pathtrace.opnsense_config import parse_document
from netcontrol.routes.security_events import host_suppressed, source_muted
from netcontrol.routes.topology_availability import deliver_alert
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.opnsense")

PROVIDER = "opnsense"
ALERT_TYPE = "opnsense_rule_change"
METRICS = {"any_any": "opnsense_rule_any_any", "shadowed": "opnsense_rule_shadowed"}
RESOLVED_BY = "auto-resolved"
MAX_ALERTS_PER_BACKUP = 25


def dedup_key(host_id: int, kind: str, rule_key: str) -> str:
    """One open alert per host, finding kind and rule."""
    return f"opnsense-rule:{int(host_id)}:{kind}:{rule_key}"


def severity_of(finding: dict[str, Any]) -> str:
    if finding["kind"] == "shadowed" and finding.get("shadow") != "conflicting":
        return "info"
    return "warning"


def _endpoint(text: Any, port: Any) -> str:
    return f"{text or 'any'}" + (f" port {port}" if port and port != "any" else "")


def _rule_text(finding: dict[str, Any]) -> str:
    interfaces = ", ".join(finding.get("interfaces") or []) or "every interface"
    description = f' "{finding["description"]}"' if finding.get("description") else ""
    return (
        f"rule #{finding['number']}{description} on {interfaces} "
        f"({finding['action']} {finding.get('protocol') or 'any'} "
        f"from {_endpoint(finding['source'], finding.get('source_port'))} "
        f"to {_endpoint(finding['destination'], finding.get('destination_port'))})"
    )


def alert_message(finding: dict[str, Any], device: str) -> str:
    """The alert text of one finding (parsed rule fields only)."""
    if finding["kind"] == "any_any":
        return f"OPNsense {device}: new any-to-any pass {_rule_text(finding)}"
    how = "does the opposite" if finding.get("shadow") == "conflicting" else "does the same"
    return (
        f"OPNsense {device}: {_rule_text(finding)} is now shadowed by rule #{finding['shadowed_by']}, "
        f"which takes every flow it matches first and {how}"
    )


def summary_text(result: dict[str, Any]) -> str:
    """The "Rule changes" row of the firewall's "Config backup" section."""
    if result.get("compared") is False:
        return "Nothing to compare with yet (first backup of this host)"
    counts = result["summary"]
    parts = []
    if counts.get("any_any"):
        n = counts["any_any"]
        parts.append(f"{n} new any-to-any rule{'s' if n != 1 else ''}")
    if counts.get("shadowed"):
        n = counts["shadowed"]
        parts.append(f"{n} newly shadowed rule{'s' if n != 1 else ''}")
    if not parts:
        text = "No new any-to-any or shadowed rules"
    else:
        done = []
        if result["alerted"]:
            done.append("alerts raised")
        if result["muted"]:
            done.append(f"{result['muted']} muted or suppressed")
        if result["skipped"]:
            done.append(f"{result['skipped']} over the limit of {MAX_ALERTS_PER_BACKUP} not alerted")
        text = ", ".join(parts) + (f"; {', '.join(done)}" if done else "")
    if result["resolved"]:
        text += f"; {result['resolved']} earlier alert{'s' if result['resolved'] != 1 else ''} resolved"
    return text


async def _previous_text(host_id: int, backup_id: int) -> str | None:
    """The config text of the host's successful backup before ``backup_id``."""
    recent = await db.get_config_backups(host_id=host_id, limit=2, status="success")
    previous = next((b for b in recent if int(b["id"]) != int(backup_id)), None)
    if previous is None:
        return None
    row = await db.get_config_backup(int(previous["id"]))
    return str((row or {}).get("config_text") or "")


def _compare(previous: str | None, config_xml: str) -> dict[str, Any] | bool | None:
    """The findings of the change from ``previous`` to ``config_xml``:
    ``None`` when ``config_xml`` is no OPNsense configuration, ``False``
    when there is nothing to compare it with. Parsing and the shadow
    analysis are CPU work: run off the event loop."""
    after = parse_document(config_xml)
    if after is None:
        return None
    before = parse_document(previous) if previous else None
    if before is None:
        return False
    return rule_change_findings(before, after)


async def alert_rule_changes(
    host: dict, backup_id: int, config_xml: str, *, org_ref: int | None = None
) -> dict[str, Any] | None:
    """Raise and resolve the rule change alerts of the host's new backup
    ``backup_id`` (``config_xml``), against its previous successful backup.
    ``org_ref``: the collecting source, whose firewall mute covers the
    alerts. ``None`` when ``config_xml`` is no OPNsense configuration."""
    host_id = int(host["id"])
    result: dict[str, Any] = {
        "compared": False,
        "summary": {},
        "alerted": 0,
        "muted": 0,
        "skipped": 0,
        "resolved": 0,
        "new": [],
    }
    found = await asyncio.to_thread(_compare, await _previous_text(host_id, backup_id), config_xml)
    if found is None:
        return None
    if not isinstance(found, dict):
        return result
    result.update(compared=True, summary=found["summary"], new=found["new"])
    for finding in found["gone"]:
        result["resolved"] += await db.resolve_monitoring_alerts(
            dedup_key(host_id, finding["kind"], str(finding["key"])), RESOLVED_BY
        )
    if not found["new"]:
        return result
    if org_ref is not None and await source_muted(PROVIDER, int(org_ref)):
        result["muted"] = len(found["new"])
        return result
    device = str(host.get("hostname") or host.get("ip_address") or f"host {host_id}")
    for finding in found["new"]:
        metric = METRICS[finding["kind"]]
        if await host_suppressed(host, metric):
            result["muted"] += 1
            continue
        if result["alerted"] >= MAX_ALERTS_PER_BACKUP:
            result["skipped"] += 1
            continue
        try:
            await deliver_alert(
                host_id=host_id,
                name=device,
                alert_type=ALERT_TYPE,
                metric=metric,
                message=alert_message(finding, device),
                severity=severity_of(finding),
                dedup_key=dedup_key(host_id, finding["kind"], str(finding["key"])),
            )
            result["alerted"] += 1
        except Exception as exc:  # noqa: BLE001 - one failed alert never stops the others
            LOGGER.warning("opnsense: rule change alert of host %s not raised: %s", host_id, type(exc).__name__)
    if result["alerted"]:
        LOGGER.info("opnsense: %s rule change alert(s) raised for host %s", result["alerted"], host_id)
    return result
