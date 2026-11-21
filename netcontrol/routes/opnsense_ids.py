"""
opnsense_ids.py -- The intrusion detection (Suricata) alerts of an OPNsense
firewall, kept as security events.

Three paths read them over the source's API key
(``collector.collect_ids_alerts``: the IDS status, then only the alerts
newer than the newest one stored, see ``netcontrol.integrations.opnsense.ids``)
and hand the events to ``security_events.record_events``, which stores them
and raises one alert per firewall and signature:

  - every stored collection (``store_collected``, from
    ``opnsense_collection.after_collection``), which also gives the
    firewall's details an "IDS alerts" section (status, what this read
    stored, the counts of the last ``SECTION_WINDOW_HOURS``) and a "Newest
    IDS alerts" table;
  - every monitoring poll of a firewall that is an inventory host, in the
    poll's API session (``read_in_session``, from
    ``opnsense_health.read_firewall``), so an alert arrives within a poll
    interval. A source whose last read found the IDS disabled (or no IDS
    API) is not read by the poll until a collection finds it enabled
    (``poll_wanted``);
  - a forwarded Suricata syslog alert line (``syslog_rules`` reason
    ``ids``): ``read_source_now``, with the re-collection trigger's
    debounce (``netcontrol.source_recollect``).

The read and the store of one source never overlap with themselves
(``security_events`` locks per source), and an alert read twice is stored
once. Best-effort: a failure is logged and never fails a collection or a
poll.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import routes.database as db

from netcontrol.integrations.meraki.normalize import _add, kv_section, table_section
from netcontrol.integrations.opnsense.client import OpnsenseApiError, OpnsenseClient
from netcontrol.integrations.opnsense.collector import collect_ids_alerts, sanitize_options
from netcontrol.integrations.opnsense.ids import (
    KIND_IDS_ALERT,
    STATUS_DISABLED,
    STATUS_UNAVAILABLE,
    alert_events,
)
from netcontrol.integrations.opnsense.normalize import PROVIDER
from netcontrol.integrations.traffic import store_time
from netcontrol.routes import security_events
from netcontrol.routes.opnsense_collection import _firewall
from netcontrol.telemetry import configure_logging, redact_value

LOGGER = configure_logging("plexus.opnsense")

SECTION_IDS = "IDS alerts"
SECTION_IDS_NEWEST = "Newest IDS alerts"
SECTION_WINDOW_HOURS = 24
NEWEST_SHOWN = 5
# The poll's IDS read: each call, and its single retry.
POLL_TIMEOUT_SECONDS = 15.0

STATUS_TEXT = {
    "running": "Running",
    "stopped": "Enabled, not running (the alerts it logged are read)",
    STATUS_DISABLED: "Disabled on the firewall: no alerts read",
    STATUS_UNAVAILABLE: "This OPNsense release has no IDS API: no alerts read",
}

# Sources whose last read found the IDS off or missing: the poll skips them.
_IDS_OFF: set[int] = set()


def poll_wanted(org_ref: int) -> bool:
    """Whether the monitoring poll reads the IDS of source ``org_ref``."""
    return int(org_ref) not in _IDS_OFF


def note_status(org_ref: int, ids: dict | None) -> None:
    """Remember whether the source's IDS is off (see ``poll_wanted``)."""
    if isinstance(ids, dict) and ids.get("status") in (STATUS_DISABLED, STATUS_UNAVAILABLE):
        _IDS_OFF.add(int(org_ref))
    elif isinstance(ids, dict):
        _IDS_OFF.discard(int(org_ref))


def forget() -> None:
    """Forget the sources found off (tests)."""
    _IDS_OFF.clear()


async def read_state(org_ref: int) -> dict[str, Any]:
    """What a read of the source starts from: ``since`` (the newest event
    stored) and ``classtypes`` (sid -> category already stored). Never
    raises: an empty state reads the first pages."""
    try:
        return {
            "since": await db.security_event_watermark(PROVIDER, org_ref, KIND_IDS_ALERT),
            "classtypes": await db.security_event_categories(PROVIDER, org_ref, KIND_IDS_ALERT),
        }
    except Exception as exc:  # noqa: BLE001 - read from the start instead
        LOGGER.warning("opnsense ids: state of source %s not read: %s", org_ref, type(exc).__name__)
        return {"since": None, "classtypes": {}}


async def record(
    org_ref: int, source_name: str, ids: dict | None, host: dict | None, state: dict | None = None
) -> dict[str, Any]:
    """Store the events of one IDS read and raise their alerts. Never
    raises (an empty outcome on failure)."""
    note_status(org_ref, ids)
    outcome: dict[str, Any] = {"stored": [], "alerted": 0, "muted": 0, "repeated": 0}
    events = alert_events(ids, (state or {}).get("classtypes"))
    if not events:
        return outcome
    try:
        return await security_events.record_events(PROVIDER, org_ref, events, host=host, source_name=source_name)
    except Exception as exc:  # noqa: BLE001 - the collection or poll goes on
        LOGGER.warning("opnsense ids: alerts of source %s not stored: %s", org_ref, type(exc).__name__)
        return outcome


async def read_in_session(
    client: OpnsenseClient, org_ref: int, errors: list[dict[str, Any]]
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """Read the source's IDS alerts in an open API session: ``(the read,
    the state it started from)``. A rejected key or an unreachable firewall
    raises."""
    state = await read_state(org_ref)
    ids, _calls, _answered = await collect_ids_alerts(
        client, errors, since=state["since"], classtypes=state["classtypes"]
    )
    return ids, state


async def _section_rows(
    ids: dict | None, outcome: dict[str, Any], org_ref: int, host: dict | None
) -> tuple[list[tuple[str, Any]], list[list[Any]]]:
    """The rows of the "IDS alerts" section and of the newest-alerts table."""
    if ids is None:
        return [("Status", "Not read: see the collection warnings")], []
    status = str(ids.get("status") or "")
    rows: list[tuple[str, Any]] = [("Status", STATUS_TEXT.get(status, status or "unknown"))]
    if status in (STATUS_DISABLED, STATUS_UNAVAILABLE):
        return rows, []
    rows.append(("New alerts stored", len(outcome["stored"])))
    if outcome["alerted"] or outcome["muted"]:
        rows.append(("Alerts raised", f"{outcome['alerted']} raised, {outcome['muted']} muted"))
    if ids.get("truncated"):
        rows.append(("Read limit", "More new alerts than one read takes: the oldest of them were not read"))
    if ids.get("lookups_skipped"):
        rows.append(("Severity", f"{ids['lookups_skipped']} new signature(s) not looked up yet: severity unknown"))
    since = store_time(datetime.now(UTC) - timedelta(hours=SECTION_WINDOW_HOURS))
    newest: list[list[Any]] = []
    try:
        counts = await db.count_security_events(PROVIDER, org_ref, KIND_IDS_ALERT, since)
        rows.append(
            (
                f"Last {SECTION_WINDOW_HOURS} h",
                f"{counts['total']}: {counts['critical']} critical, {counts['warning']} warning, "
                f"{counts['info']} info, {counts['unknown']} unknown; {counts['blocked']} blocked",
            )
        )
        found = await db.list_security_events(
            provider=PROVIDER, org_ref=org_ref, kind=KIND_IDS_ALERT, since=since, limit=NEWEST_SHOWN
        )
        newest = [
            [
                e["occurred_at"],
                e["severity"],
                e["action"],
                f"{e['signature']} (sid {e['signature_id']})",
                security_events.endpoint_text(e["src_ip"], e["src_port"]),
                security_events.endpoint_text(e["dest_ip"], e["dest_port"]),
            ]
            for e in found["events"]
        ]
    except Exception as exc:  # noqa: BLE001 - the section is shown without the counts
        LOGGER.warning("opnsense ids: counts of source %s not read: %s", org_ref, type(exc).__name__)
    rows.append(
        (
            "Alerting",
            "Monitoring alerts on "
            + str(host.get("hostname") or host.get("ip_address"))
            + ", read every monitoring poll"
            if host
            else "Notification channels only: import the firewall into the inventory for monitoring alerts "
            "and a read every poll",
        )
    )
    rows.append(("Source", "Suricata alerts over the OPNsense API (ids/service/query_alerts)"))
    return rows, newest


async def store_collected(raw: dict, snapshot: dict, org_ref: int, host: dict | None) -> dict[str, Any] | None:
    """Store the IDS alerts of a collection (``ids_alerts``, popped from
    ``raw``: never part of the snapshot) for the firewall's inventory host
    ``host`` (``None``: not one), and add the "IDS alerts" sections to the
    firewall. ``None`` when the option is off."""
    if "ids_alerts" not in raw:
        return None
    ids = raw.pop("ids_alerts")
    if not (raw.get("options") or {}).get("include_ids_alerts", True):
        return None
    name = str((snapshot.get("org") or {}).get("name") or (raw.get("firewall") or {}).get("name") or "")
    outcome = await record(org_ref, name, ids, host, raw.pop("ids_state", None))
    rows, newest = await _section_rows(ids, outcome, org_ref, host)
    firewall = _firewall(snapshot)
    if firewall is not None:
        _add(firewall["sections"], kv_section(SECTION_IDS, rows))
        _add(
            firewall["sections"],
            table_section(
                SECTION_IDS_NEWEST,
                ["Time (UTC)", "Severity", "Action", "Signature", "Source", "Destination"],
                newest,
            ),
        )
    return outcome


async def _source_host(org_ref: int) -> dict | None:
    """The inventory host the newest collection of the source matched its
    firewall to, or ``None``."""
    # Imported here: opnsense_health imports this module.
    from netcontrol.routes.opnsense_health import SUMMARY_KEY

    rows = await db.list_meraki_snapshots(int(org_ref), 1)
    host_id = (rows[0].get("summary") or {}).get(SUMMARY_KEY) if rows else None
    return await db.get_host(int(host_id)) if host_id else None


async def read_source_now(org_ref: int) -> str:
    """Read and store the IDS alerts of source ``org_ref`` now (a forwarded
    Suricata syslog line asked for it). Returns ``completed``, ``skipped``
    (no such OPNsense source, no key, the option or automatic collection
    off) or ``failed``."""
    # Imported here: meraki_topology imports the routes of every source.
    from netcontrol.routes.meraki_topology import _opnsense_client, _provider_of

    org = await db.get_meraki_org(org_ref)
    if not org or _provider_of(org) != PROVIDER or not org.get("has_api_key"):
        return "skipped"
    options = sanitize_options(org.get("options"))
    if not options["include_ids_alerts"] or not org.get("auto_collect", True):
        return "skipped"
    secret = await db.get_meraki_org_api_key(org_ref)
    if not secret:
        return "skipped"
    errors: list[dict[str, Any]] = []
    try:
        async with _opnsense_client(org, secret, options, max_retries=1, timeout=POLL_TIMEOUT_SECONDS) as client:
            ids, state = await read_in_session(client, org_ref, errors)
    except OpnsenseApiError as exc:
        LOGGER.warning("opnsense ids: source %s not read: %s", org.get("name") or org_ref, redact_value(str(exc)))
        return "failed"
    except Exception as exc:  # noqa: BLE001 - the trigger goes on
        LOGGER.warning("opnsense ids: source %s not read: %s", org.get("name") or org_ref, type(exc).__name__)
        return "failed"
    for error in errors:
        LOGGER.debug("opnsense ids: %s", redact_value(str(error.get("message") or "")))
    host = None
    try:
        host = await _source_host(org_ref)
    except Exception as exc:  # noqa: BLE001 - stored without the host
        LOGGER.warning("opnsense ids: host of source %s not read: %s", org_ref, type(exc).__name__)
    await record(org_ref, str(org.get("name") or ""), ids, host, state)
    return "completed" if ids is not None else "failed"
