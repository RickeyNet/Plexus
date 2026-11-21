"""
opnsense_filterlog.py -- Live pass / block evidence of OPNsense filter rules.

An OPNsense firewall that forwards its firewall log to the syslog receiver
sends one ``filterlog`` line per logged packet. The receiver's batch writer
(``metrics_engine._trap_event_writer_loop``) hands each flushed batch to
``divert`` once the source addresses are resolved to inventory hosts:

  - the filterlog lines come out of the batch, so they are never stored in
    ``trap_syslog_events`` nor run through the syslog alert rules;
  - the line of an inventory host is summed into the in-memory
    ``AGGREGATOR`` (``netcontrol.integrations.opnsense.filterlog``); one from
    an address that is no inventory host is counted and dropped, as is every
    line while ``filterlog_evidence`` (``state.EVENT_RECEIVER_CONFIG``, on
    when unset) is off;
  - every ``FLUSH_SECONDS`` the aggregate is written by a batched upsert
    (``routes.db.opnsense_filterlog``) and kept ``RETENTION_DAYS``.

What the evidence is shown on:

  - ``rules_evidence``: the rules view (``opnsense_rules.get_host_rules``)
    gains each rule's passes and blocks in the last hour and the last
    ``WINDOW_HOURS``, when it was last logged and its recent flows, tied by
    the rule's pf label (``FilterRule.label``); the labels no rule of the
    configuration has (default deny, anti-lockout, bogons, a rule removed
    since the backup) are listed on their own;
  - ``attach_trace_evidence``: a path trace hop through an inventory host
    with evidence gains ``log_evidence``: the evidence of the rule the trace
    names and whether a logged flow matches the traced one, with the
    contradiction spelled out when the log disagrees with the trace. Only
    the server adds it: the offline bundle never carries it, and a trace
    without evidence is returned as it is.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterable
from typing import Any

import routes.database as db

import netcontrol.routes.state as state
from netcontrol.integrations.opnsense.filterlog import (
    BUCKET_SECONDS,
    FilterlogAggregator,
    bucket_start,
    filterlog_payload,
    is_filterlog,
)
from netcontrol.integrations.pathtrace.model import ACL, BLOCKED, OK, contains, net
from netcontrol.integrations.pathtrace.opnsense_config import FilterRule, OpnsenseConfig, parse_document
from netcontrol.telemetry import configure_logging, redact_value

LOGGER = configure_logging("plexus.opnsense")

FLUSH_SECONDS = 30.0
RETENTION_DAYS = 7
WINDOW_HOURS = 24
RECENT_HOURS = 1
# Flows kept per host, rule and action; and shown per rule.
FLOWS_PER_RULE = 25
FLOWS_SHOWN = 5
SWITCH = "filterlog_evidence"

AGGREGATOR = FilterlogAggregator()
_flush_task: asyncio.Task | None = None


def evidence_enabled() -> bool:
    """The ``filterlog_evidence`` switch (on when unset)."""
    return bool(state.EVENT_RECEIVER_CONFIG.get(SWITCH, True))


# ── Receiver ─────────────────────────────────────────────────────────────────


def divert(rows: list[tuple]) -> list[tuple]:
    """The rows of a flushed receiver batch (``(source_ip, host_id,
    event_type, facility, severity, oid, message, raw_data)``) without the
    filterlog lines, which are summed into ``AGGREGATOR`` (or counted and
    dropped). A message that only mentions filterlog stays. Never raises."""
    kept: list[tuple] = []
    counted = False
    enabled = evidence_enabled()
    for row in rows:
        message = row[6] if len(row) > 6 else ""
        payload = filterlog_payload(message) if row[2] == "syslog" and is_filterlog(message) else None
        if payload is None:
            kept.append(row)
            continue
        try:
            if not enabled:
                AGGREGATOR.count("disabled")
            elif row[1] is None:
                AGGREGATOR.count("unknown_source")
            else:
                counted = AGGREGATOR.add(int(row[1]), payload) or counted
        except Exception as exc:  # noqa: BLE001 - a bad line never stops the batch
            AGGREGATOR.count("unparsed")
            LOGGER.debug("opnsense: filterlog line not counted: %s", type(exc).__name__)
    if counted:
        _ensure_flusher()
    return kept


def _ensure_flusher() -> None:
    global _flush_task
    if _flush_task is None or _flush_task.done():
        try:
            _flush_task = asyncio.ensure_future(_flush_loop())
        except RuntimeError:  # no running loop (a synchronous caller): flushed by the next one
            _flush_task = None


async def flush() -> int:
    """Write what ``AGGREGATOR`` summed since the last flush. A failed write
    drops it (counted): the log keeps coming, and evidence is a sample."""
    hits, flows = AGGREGATOR.drain()
    if not hits and not flows:
        return 0
    try:
        return await db.upsert_opnsense_filterlog(hits, flows, FLOWS_PER_RULE)
    except Exception as exc:  # noqa: BLE001 - the next flush starts over
        AGGREGATOR.count("dropped", sum(int(row[6]) for row in hits))
        LOGGER.warning("opnsense: firewall log evidence not written: %s", redact_value(str(exc)))
        return 0


async def _flush_loop() -> None:
    while True:
        await asyncio.sleep(FLUSH_SECONDS)
        await flush()


def receiver_stats() -> dict[str, int]:
    """The filterlog counters since Plexus started, for the receiver status."""
    counters = AGGREGATOR.stats()
    return {
        "filterlog_received": counters["lines"],
        "filterlog_dropped": counters["unknown_source"] + counters["disabled"] + counters["dropped"],
        "filterlog_unknown_source": counters["unknown_source"],
        "filterlog_pending": AGGREGATOR.pending(),
    }


async def delete_old_evidence() -> int:
    return await db.delete_old_opnsense_filterlog(RETENTION_DAYS)


# ── Evidence ─────────────────────────────────────────────────────────────────


def _windows(now: float) -> tuple[str, str]:
    """The bucket starts of the evidence window and of the last hour."""
    return bucket_start(now - WINDOW_HOURS * 3600), bucket_start(now - RECENT_HOURS * 3600)


def describe_key(key: str) -> str:
    """What a rule key names when no rule of the configuration has it."""
    if key.startswith("rulenr:"):
        return f"pf rule {key.removeprefix('rulenr:')} (logged without a label)"
    if len(key) == 36 and key.count("-") == 4:
        return "A rule that is not in the newest backup"
    return "An automatic or internal rule (default deny, anti-lockout, bogons...)"


def _empty() -> dict[str, Any]:
    return {"passes": 0, "blocks": 0, "passes_recent": 0, "blocks_recent": 0, "last_seen": "", "seen_on": []}


def summarize(rows: list[dict]) -> dict[str, dict[str, Any]]:
    """``rule_key -> evidence`` of summary rows
    (``get_opnsense_filterlog_rule_summary``)."""
    found: dict[str, dict[str, Any]] = {}
    for row in rows:
        entry = found.setdefault(row["rule_key"], _empty())
        word = "passes" if row["action"] == "pass" else "blocks"
        entry[word] += int(row["hits"])
        entry[f"{word}_recent"] += int(row["recent_hits"])
        entry["last_seen"] = max(entry["last_seen"], str(row["last_seen"] or ""))
        where = " ".join(p for p in (row.get("interface"), row.get("direction")) if p)
        if where and where not in entry["seen_on"]:
            entry["seen_on"].append(where)
    for entry in found.values():
        entry["seen_on"].sort()
    return found


def _flow_view(flow: dict) -> dict[str, Any]:
    return {
        k: flow[k] for k in ("action", "source", "destination", "protocol", "destination_port", "hits", "last_seen")
    }


def rule_key_of(rule: FilterRule, keys: Iterable[str]) -> str:
    """The key the evidence names ``rule`` by: its pf label, else its uuid."""
    have = set(keys)
    for key in (rule.label, rule.uuid):
        if key and key in have:
            return key
    return rule.label or rule.uuid


async def rules_evidence(host_id: int, config: OpnsenseConfig, view: dict[str, Any], now: float | None = None) -> None:
    """Add the evidence to a rules view of ``config`` (``rules.analyze``):
    ``log_evidence`` on each rule (``None`` without), and ``log_evidence``
    of the view: when evidence was last received, the windows, whether it
    is collected, and the labels no rule has (``unmatched``)."""
    moment = time.time() if now is None else now
    since, recent = _windows(moment)
    by_key = summarize(await db.get_opnsense_filterlog_rule_summary(host_id, since, recent))
    flows: dict[str, list[dict]] = {}
    if by_key:
        for flow in await db.get_opnsense_filterlog_flows(host_id, since, by_key.keys()):
            listed = flows.setdefault(flow["rule_key"], [])
            if len(listed) < FLOWS_SHOWN:
                listed.append(_flow_view(flow))
    used: set[str] = set()
    labels = {rule.number: rule_key_of(rule, by_key) for rule in config.rules}
    for item in view.get("rules") or []:
        key = labels.get(item.get("number"), "")
        evidence = by_key.get(key)
        item["log_evidence"] = {**evidence, "rule_key": key, "flows": flows.get(key, [])} if evidence else None
        if evidence:
            used.add(key)
    unmatched = [
        {**evidence, "rule_key": key, "name": describe_key(key), "flows": flows.get(key, [])}
        for key, evidence in sorted(by_key.items(), key=lambda pair: pair[1]["last_seen"], reverse=True)
        if key not in used
    ]
    view["log_evidence"] = {
        "enabled": evidence_enabled(),
        "received_at": await db.get_opnsense_filterlog_last_seen(host_id) or None,
        "window_hours": WINDOW_HOURS,
        "recent_hours": RECENT_HOURS,
        "bucket_seconds": BUCKET_SECONDS,
        "unmatched": unmatched,
    }


# ── Path trace ───────────────────────────────────────────────────────────────


def flow_matches(flow: dict, source: Any, destination: Any, protocol: str, port: int | None) -> bool:
    """Whether a logged flow is the traced one: its addresses inside the
    traced source and destination (networks or addresses), the traced
    protocol (empty: any) and destination port (``None``: any)."""
    src, dst = net(flow.get("source")), net(flow.get("destination"))
    if src is None or dst is None or source is None or destination is None:
        return False
    if not (contains(source, src) and contains(destination, dst)):
        return False
    wanted = (protocol or "").strip().lower()
    if wanted in ("icmp6", "ipv6-icmp"):
        wanted = "icmpv6"
    if wanted and wanted not in ("any", "all") and str(flow.get("protocol") or "") != wanted:
        return False
    return port is None or flow.get("destination_port") == port


def _trace_says(hop: dict) -> str:
    statuses = [i.get("status") for i in hop.get("items") or [] if i.get("stage") == ACL]
    if BLOCKED in statuses:
        return "blocked"
    return "allowed" if OK in statuses else ""


def contradiction(trace_says: str, passes: int, blocks: int) -> str:
    """The sentence that says the log disagrees with the trace ("" when it does not)."""
    if trace_says == "allowed" and blocks and not passes:
        return f"The trace allows this flow here, but the firewall log shows it blocked {blocks} times."
    if trace_says == "blocked" and passes and not blocks:
        return f"The trace blocks this flow here, but the firewall log shows it passed {passes} times."
    if trace_says and passes and blocks:
        return f"The firewall log shows this flow both passed ({passes}) and blocked ({blocks})."
    return ""


def _rule_name(key: str, names: dict[str, FilterRule]) -> str:
    rule = names.get(key)
    if rule is None:
        return describe_key(key)
    return f"rule {rule.number}" + (f" ({rule.description})" if rule.description else "")


def hop_evidence(
    hop: dict,
    config: OpnsenseConfig | None,
    by_key: dict[str, dict[str, Any]],
    flows: list[dict],
    traced: tuple[Any, Any, str, int | None],
) -> dict[str, Any]:
    """The ``log_evidence`` of one hop through a firewall with evidence."""
    rules = {rule.number: rule for rule in (config.rules if config else [])}
    names = {rule_key_of(rule, by_key): rule for rule in rules.values()}
    named: list[dict[str, Any]] = []
    for item in hop.get("items") or []:
        number = item.get("rule")
        if item.get("stage") != ACL or not isinstance(number, int) or number not in rules:
            continue
        rule = rules[number]
        key = rule_key_of(rule, by_key)
        if any(r["number"] == number for r in named):
            continue
        evidence = by_key.get(key) or _empty()
        named.append(
            {
                "number": number,
                "description": rule.description,
                "rule_key": key,
                "logs_packets": rule.log,
                **{k: evidence[k] for k in ("passes", "blocks", "last_seen")},
            }
        )
    matched = [f for f in flows if flow_matches(f, *traced)]
    passes = sum(f["hits"] for f in matched if f["action"] == "pass")
    blocks = sum(f["hits"] for f in matched if f["action"] == "block")
    says = _trace_says(hop)
    flow: dict[str, Any] | None = None
    if traced[0] is not None and traced[1] is not None:
        by = [_rule_name(f["rule_key"], names) for f in matched]
        flow = {
            "matched": bool(matched),
            "passes": passes,
            "blocks": blocks,
            "last_seen": max((f["last_seen"] for f in matched), default=""),
            "rules": list(dict.fromkeys(by)),
        }
    return {
        "window_hours": WINDOW_HOURS,
        "trace_says": says,
        "rules": named,
        "flow": flow,
        "contradiction": contradiction(says, passes, blocks),
    }


async def attach_trace_evidence(
    result: dict[str, Any], source: str, destination: str, protocol: str = "", port: int | None = None
) -> dict[str, Any]:
    """Add ``log_evidence`` to each request hop of a path trace that passes
    an inventory host with firewall log evidence in the window. Returns
    ``result``; on any error it is returned as it was."""
    try:
        await _attach(result, source, destination, protocol, port)
    except Exception as exc:  # noqa: BLE001 - evidence never breaks a trace
        LOGGER.warning("opnsense: firewall log evidence not added to the trace: %s", redact_value(str(exc)))
    return result


async def _attach(result: dict[str, Any], source: str, destination: str, protocol: str, port: int | None) -> None:
    hops = [h for h in (result.get("request") or {}).get("hops") or [] if isinstance(h, dict)]
    candidates = {h["node"] for h in hops if isinstance(h.get("node"), int) and not isinstance(h.get("node"), bool)}
    if not candidates:
        return
    since, recent = _windows(time.time())
    hosts = await db.hosts_with_opnsense_filterlog(candidates, since)
    if not hosts:
        return
    backups = await db.get_latest_config_texts_for_hosts(sorted(hosts))
    traced = (net(source), net(destination), protocol, port)
    for host_id in sorted(hosts):
        backup = backups.get(host_id)
        config = parse_document(str(backup.get("config_text") or "")) if backup else None
        by_key = summarize(await db.get_opnsense_filterlog_rule_summary(host_id, since, recent))
        flows = await db.get_opnsense_filterlog_flows(host_id, since)
        for hop in hops:
            if hop.get("node") == host_id:
                hop["log_evidence"] = hop_evidence(hop, config, by_key, flows, traced)
