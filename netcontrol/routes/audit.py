"""
audit.py -- Network audit report engine.

Runs a set of pluggable :class:`Rule` checks against the live inventory and
config baselines, producing :class:`Finding` rows that are persisted into
``audit_findings`` and surfaced through ``/api/audit/...`` endpoints.

Rule packs wired in ``_RULE_REGISTRY``: config drift, port hygiene,
VLAN consistency across trunks, and management-plane security posture.
New packs slot in by appending a class to the registry.

The orchestrator is patterned on ``reporting._report_scheduler_loop``:
a single background task polls for due runs (cron-style schedule) and
also services on-demand ``POST /api/audit/runs`` triggers.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import dataclass, field

import routes.database as db
from fastapi import APIRouter, HTTPException, Query

from netcontrol.routes.shared import _compute_config_diff
from netcontrol.telemetry import configure_logging, increment_metric, redact_value

LOGGER = configure_logging("plexus.audit")

router = APIRouter()

AUDIT_POLL_SECONDS = max(30, int(os.getenv("APP_AUDIT_POLL_SECONDS", "60")))


# ── Domain types ────────────────────────────────────────────────────────────

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


@dataclass
class Finding:
    """One rule violation against one host."""

    rule_id: str
    category: str
    severity: str
    title: str
    detail: str = ""
    host_id: int | None = None
    cis_control: str = ""
    evidence: dict = field(default_factory=dict)


@dataclass
class AuditContext:
    """Per-run state passed to every rule.

    Rules read ``hosts`` (list of host dicts) and call back into ``db`` for
    anything else. Keeping the context small keeps rules independently
    testable.
    """

    run_id: int
    hosts: list[dict]


class Rule:
    """Base class for all audit rules.

    Subclasses set ``rule_id``, ``category``, ``default_severity`` and
    optionally ``cis_control``, then implement :meth:`evaluate`. Rules
    must be pure-ish: read from ``ctx`` and the DB, emit findings, never
    mutate inventory.
    """

    rule_id: str = ""
    category: str = ""
    default_severity: str = "info"
    cis_control: str = ""
    title: str = ""

    async def evaluate(self, ctx: AuditContext) -> list[Finding]:  # pragma: no cover
        raise NotImplementedError


# ── Rule pack: configuration drift ──────────────────────────────────────────

class ConfigDriftRule(Rule):
    """Diff each host's most recent running-config snapshot against its
    baseline. Any added/removed lines (after volatile-metadata stripping
    inside ``_compute_config_diff``) produces a single finding per host
    with the diff body as evidence.
    """

    rule_id = "config.drift"
    category = "config"
    default_severity = "high"
    cis_control = "CIS Controls v8 4.2"
    title = "Running-config drift from baseline"

    async def evaluate(self, ctx: AuditContext) -> list[Finding]:
        findings: list[Finding] = []
        for host in ctx.hosts:
            host_id = int(host["id"])
            baseline = await db.get_config_baseline_for_host(host_id)
            if not baseline or not (baseline.get("config_text") or "").strip():
                # No baseline yet -> informational finding so the user
                # knows this host is unaudited.
                findings.append(Finding(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity="info",
                    title="No config baseline captured",
                    detail=(
                        "This host has no config baseline; drift cannot "
                        "be evaluated until one is captured."
                    ),
                    host_id=host_id,
                    cis_control=self.cis_control,
                    evidence={"hostname": host.get("hostname", "")},
                ))
                continue

            snapshot = await db.get_latest_config_snapshot(host_id)
            if not snapshot or not (snapshot.get("config_text") or "").strip():
                findings.append(Finding(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity="medium",
                    title="No recent config snapshot",
                    detail=(
                        "Baseline exists but no running-config has been "
                        "captured. Run a config backup so drift can be "
                        "checked."
                    ),
                    host_id=host_id,
                    cis_control=self.cis_control,
                    evidence={"hostname": host.get("hostname", "")},
                ))
                continue

            diff_text, lines_added, lines_removed = _compute_config_diff(
                baseline["config_text"],
                snapshot["config_text"],
                baseline_label="baseline",
                actual_label="running",
            )
            if lines_added == 0 and lines_removed == 0:
                continue  # in compliance

            findings.append(Finding(
                rule_id=self.rule_id,
                category=self.category,
                severity=self.default_severity,
                title=self.title,
                detail=(
                    f"{lines_added} line(s) added, {lines_removed} line(s) "
                    f"removed vs. baseline."
                ),
                host_id=host_id,
                cis_control=self.cis_control,
                evidence={
                    "hostname": host.get("hostname", ""),
                    "lines_added": lines_added,
                    "lines_removed": lines_removed,
                    # Cap evidence size; the full diff is also accessible
                    # via the existing config-drift endpoints.
                    "diff_excerpt": diff_text[:8000],
                },
            ))
        return findings


# ── Rule pack: port hygiene ─────────────────────────────────────────────────
#
# Three sub-rules grouped into one class so they share the interface
# walk: (a) admin-up but oper-down for >= UNUSED_PORT_DAYS days,
# (b) connected port without a description, (c) speed/duplex mismatch
# against the resolved topology peer.

PORT_HYGIENE_UNUSED_DAYS = max(1, int(
    os.getenv("APP_AUDIT_UNUSED_PORT_DAYS", "30")
))


def _ticks_to_days(ticks_str: str) -> float | None:
    """ifLastChange is TimeTicks (hundredths of a second) since sysUpTime.
    We store the raw value at collection time and the rule converts that
    to a "days since last transition" approximation. Without the device's
    boot time we can't be exact, but a port that's been admin-up + oper-
    down for thirty days will have a tick value that, when divided into
    days, is essentially the device's uptime minus 30 -- still a useful
    floor for the hygiene check. The rule treats a missing/zero value
    as "unknown" and skips it rather than flagging false positives.
    """
    try:
        ticks = int(ticks_str)
    except (ValueError, TypeError):
        return None
    if ticks <= 0:
        return None
    # 100 ticks/sec * 60 * 60 * 24 = 8_640_000 ticks/day
    return ticks / 8_640_000.0


class PortHygieneRule(Rule):
    rule_id = "port.hygiene"
    category = "port"
    default_severity = "low"
    cis_control = "CIS Controls v8 12.2"
    title = "Port hygiene issues"

    async def evaluate(self, ctx: AuditContext) -> list[Finding]:
        findings: list[Finding] = []
        # Resolve which ports are connected (per topology) so we can scope
        # the missing-description and speed/duplex checks to live links.
        links = await db.get_topology_links()
        connected_ports: dict[tuple[int, str], dict] = {}
        for ln in links:
            src_id = ln.get("source_host_id")
            src_if = ln.get("source_interface") or ""
            if src_id and src_if:
                connected_ports[(int(src_id), src_if)] = ln
            tgt_id = ln.get("target_host_id")
            tgt_if = ln.get("target_interface") or ""
            if tgt_id and tgt_if:
                connected_ports[(int(tgt_id), tgt_if)] = ln

        for host in ctx.hosts:
            host_id = int(host["id"])
            hostname = host.get("hostname", "")
            ports = await db.get_interface_inventory_for_host(host_id)
            if not ports:
                continue

            for p in ports:
                name = p.get("name", "") or ""
                admin = (p.get("admin_state") or "").lower()
                oper = (p.get("oper_state") or "").lower()
                description = (p.get("description") or "").strip()
                duplex = (p.get("duplex") or "").lower()
                speed = int(p.get("speed_mbps") or 0)

                is_connected = (host_id, name) in connected_ports

                # (a) Admin-up + oper-down >= threshold days
                if admin == "up" and oper == "down":
                    age_days = _ticks_to_days(p.get("last_change") or "")
                    if age_days is not None and age_days >= PORT_HYGIENE_UNUSED_DAYS:
                        findings.append(Finding(
                            rule_id="port.unused",
                            category=self.category,
                            severity="low",
                            title="Port admin-up but oper-down",
                            detail=(
                                f"{hostname} {name}: admin-up but oper-down for "
                                f"~{int(age_days)} days. Disable unused ports per "
                                f"hardening guidance."
                            ),
                            host_id=host_id,
                            cis_control=self.cis_control,
                            evidence={
                                "hostname": hostname,
                                "port": name,
                                "approx_days_inactive": int(age_days),
                                "threshold_days": PORT_HYGIENE_UNUSED_DAYS,
                            },
                        ))

                # (b) Connected port with no description
                if is_connected and not description:
                    findings.append(Finding(
                        rule_id="port.missing_description",
                        category=self.category,
                        severity="info",
                        title="Connected port missing description",
                        detail=(
                            f"{hostname} {name}: port is connected (per "
                            f"topology) but has no interface description."
                        ),
                        host_id=host_id,
                        cis_control=self.cis_control,
                        evidence={"hostname": hostname, "port": name},
                    ))

                # (c) Speed/duplex mismatch with peer (only on connected ports
                #     with a resolved peer ifIndex we have inventory for)
                if is_connected:
                    ln = connected_ports[(host_id, name)]
                    peer_host_id = (
                        ln.get("target_host_id")
                        if ln.get("source_host_id") == host_id
                        else ln.get("source_host_id")
                    )
                    peer_if = (
                        ln.get("target_interface")
                        if ln.get("source_host_id") == host_id
                        else ln.get("source_interface")
                    )
                    if peer_host_id and peer_if:
                        peer = await db.get_interface_inventory_by_name(
                            int(peer_host_id), peer_if
                        )
                        if peer:
                            peer_speed = int(peer.get("speed_mbps") or 0)
                            peer_duplex = (peer.get("duplex") or "").lower()
                            # Only flag when both sides report a value; a 0
                            # speed or empty duplex means the device didn't
                            # answer that OID and shouldn't masquerade as a
                            # mismatch.
                            if (speed and peer_speed and speed != peer_speed) or (
                                duplex and peer_duplex
                                and duplex not in ("unknown", "")
                                and peer_duplex not in ("unknown", "")
                                and duplex != peer_duplex
                            ):
                                findings.append(Finding(
                                    rule_id="port.speed_duplex_mismatch",
                                    category=self.category,
                                    severity="medium",
                                    title="Speed/duplex mismatch with peer",
                                    detail=(
                                        f"{hostname} {name} "
                                        f"({speed}Mbps/{duplex or '?'}) "
                                        f"vs peer {peer_if} "
                                        f"({peer_speed}Mbps/{peer_duplex or '?'})."
                                    ),
                                    host_id=host_id,
                                    cis_control=self.cis_control,
                                    evidence={
                                        "hostname": hostname,
                                        "port": name,
                                        "local_speed_mbps": speed,
                                        "local_duplex": duplex,
                                        "peer_host_id": int(peer_host_id),
                                        "peer_port": peer_if,
                                        "peer_speed_mbps": peer_speed,
                                        "peer_duplex": peer_duplex,
                                    },
                                ))
        return findings


# ── Rule pack: VLAN consistency ─────────────────────────────────────────────
#
# For each resolved trunk in the topology, both endpoints should define
# the VLANs they're allowed to carry. Missing definitions on one side
# show up as "VLAN X allowed on trunk but not defined on peer", which is
# a common cause of black-holed traffic across switch boundaries.

class VlanConsistencyRule(Rule):
    rule_id = "vlan.consistency"
    category = "vlan"
    default_severity = "medium"
    cis_control = "CIS Controls v8 12.4"
    title = "VLAN consistency across trunks"

    async def evaluate(self, ctx: AuditContext) -> list[Finding]:
        findings: list[Finding] = []
        links = await db.get_topology_links()
        # Pre-load each host's defined VLANs once
        defined_by_host: dict[int, set[int]] = {}
        for host in ctx.hosts:
            host_id = int(host["id"])
            defs = await db.get_vlan_definitions_for_host(host_id)
            defined_by_host[host_id] = {
                int(d["vlan_id"]) for d in defs if d.get("vlan_id") is not None
            }

        host_by_id = {int(h["id"]): h for h in ctx.hosts}

        for ln in links:
            src_id = ln.get("source_host_id")
            tgt_id = ln.get("target_host_id")
            if not (src_id and tgt_id):
                continue  # unresolved peer -- can't compare
            src_if = ln.get("source_interface") or ""
            tgt_if = ln.get("target_interface") or ""
            src_port = await db.get_interface_inventory_by_name(int(src_id), src_if)
            tgt_port = await db.get_interface_inventory_by_name(int(tgt_id), tgt_if)
            if not src_port or not tgt_port:
                continue

            src_trunks = _parse_vlan_csv(src_port.get("trunk_vlans") or "")
            tgt_trunks = _parse_vlan_csv(tgt_port.get("trunk_vlans") or "")
            if not src_trunks and not tgt_trunks:
                continue  # neither side is a trunk

            src_defined = defined_by_host.get(int(src_id), set())
            tgt_defined = defined_by_host.get(int(tgt_id), set())

            # VLANs allowed on this trunk that the *peer* doesn't define
            # are the actionable findings -- the local side is willing
            # to forward them but the peer can't terminate them.
            src_orphans = sorted(src_trunks - tgt_defined) if tgt_defined else []
            tgt_orphans = sorted(tgt_trunks - src_defined) if src_defined else []

            if src_orphans:
                src_host = host_by_id.get(int(src_id), {})
                findings.append(Finding(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=self.default_severity,
                    title="Trunk carries VLANs not defined on peer",
                    detail=(
                        f"{src_host.get('hostname', '')} {src_if} -> peer "
                        f"{tgt_if}: VLAN(s) "
                        f"{','.join(str(v) for v in src_orphans[:20])}"
                        f"{'...' if len(src_orphans) > 20 else ''} "
                        f"allowed on trunk but not defined on peer."
                    ),
                    host_id=int(src_id),
                    cis_control=self.cis_control,
                    evidence={
                        "hostname": src_host.get("hostname", ""),
                        "port": src_if,
                        "peer_host_id": int(tgt_id),
                        "peer_port": tgt_if,
                        "orphan_vlans": src_orphans,
                    },
                ))
            if tgt_orphans:
                tgt_host = host_by_id.get(int(tgt_id), {})
                findings.append(Finding(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=self.default_severity,
                    title="Trunk carries VLANs not defined on peer",
                    detail=(
                        f"{tgt_host.get('hostname', '')} {tgt_if} -> peer "
                        f"{src_if}: VLAN(s) "
                        f"{','.join(str(v) for v in tgt_orphans[:20])}"
                        f"{'...' if len(tgt_orphans) > 20 else ''} "
                        f"allowed on trunk but not defined on peer."
                    ),
                    host_id=int(tgt_id),
                    cis_control=self.cis_control,
                    evidence={
                        "hostname": tgt_host.get("hostname", ""),
                        "port": tgt_if,
                        "peer_host_id": int(src_id),
                        "peer_port": src_if,
                        "orphan_vlans": tgt_orphans,
                    },
                ))
        return findings


def _parse_vlan_csv(csv_value: str) -> set[int]:
    out: set[int] = set()
    for part in (csv_value or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.add(int(part))
        except (ValueError, TypeError):
            continue
    return out


# ── Rule pack: security posture ─────────────────────────────────────────────
#
# Reads each host's most recent running-config snapshot (same source as
# ConfigDriftRule) and pattern-matches well-known weak-posture indicators.
# Six sub-findings grouped under one rule_id so a host that's missing
# multiple controls still surfaces every gap on the report:
#
#   - security.snmp_v2:        SNMPv1/v2c community present (no SNMPv3)
#   - security.default_community: community string is "public" or "private"
#   - security.telnet_enabled: vty allows telnet (transport input telnet)
#   - security.http_enabled:   ip http server (cleartext mgmt) enabled
#   - security.weak_password:  enable/username "password" (type 0 or type 7)
#                              found instead of "secret" (type 5/8/9)
#   - security.no_aaa:         no `aaa new-model` line (local-only auth)
#
# All map to CIS Controls v8 4.1/4.6 (secure configuration of management
# protocols and accounts). The rule deliberately doesn't try to *parse*
# the config -- regex on stripped lines is good enough for posture flags
# and keeps the rule trivially portable across IOS/IOS-XE/NX-OS.

_SECURITY_PATTERNS = {
    # (rule_id_suffix, severity, title, regex, requires_absence)
    # requires_absence=True means a finding fires when the regex does NOT match.
    "snmp_v2": (
        "high",
        "SNMPv1/v2c community in use",
        re.compile(r"^\s*snmp-server\s+community\s+", re.MULTILINE | re.IGNORECASE),
        False,
    ),
    "default_community": (
        "critical",
        "Default SNMP community string",
        re.compile(
            r"^\s*snmp-server\s+community\s+(public|private)\b",
            re.MULTILINE | re.IGNORECASE,
        ),
        False,
    ),
    "telnet_enabled": (
        "high",
        "Telnet enabled on VTY lines",
        re.compile(
            r"^\s*transport\s+input\s+.*\btelnet\b",
            re.MULTILINE | re.IGNORECASE,
        ),
        False,
    ),
    "http_enabled": (
        "medium",
        "Cleartext HTTP management enabled",
        re.compile(
            r"^\s*ip\s+http\s+server\b(?!\s+secure)",
            re.MULTILINE | re.IGNORECASE,
        ),
        False,
    ),
    "weak_password": (
        "high",
        "Weak password storage (type 0 or type 7)",
        # Matches `password 0 ...`, `password 7 ...`, `enable password ...`
        # (without `secret`), or `username X password ...`. Skips `secret`
        # forms (type 5/8/9) which are properly hashed.
        re.compile(
            r"^\s*(?:enable\s+password|"
            r"username\s+\S+\s+(?:privilege\s+\d+\s+)?password|"
            r"password\s+[07])\b",
            re.MULTILINE | re.IGNORECASE,
        ),
        False,
    ),
    "no_aaa": (
        "medium",
        "AAA not enabled (no `aaa new-model`)",
        re.compile(r"^\s*aaa\s+new-model\b", re.MULTILINE | re.IGNORECASE),
        True,  # finding fires when this is absent
    ),
}


class SecurityPostureRule(Rule):
    rule_id = "security.posture"
    category = "security"
    default_severity = "high"
    cis_control = "CIS Controls v8 4.1/4.6"
    title = "Insecure management-plane configuration"

    async def evaluate(self, ctx: AuditContext) -> list[Finding]:
        findings: list[Finding] = []
        for host in ctx.hosts:
            host_id = int(host["id"])
            snapshot = await db.get_latest_config_snapshot(host_id)
            config_text = (snapshot or {}).get("config_text") or ""
            if not config_text.strip():
                # ConfigDriftRule already surfaces "no snapshot" -- don't
                # double-report. Just skip posture checks for this host.
                continue

            for suffix, (severity, title, pattern, requires_absence) in (
                _SECURITY_PATTERNS.items()
            ):
                match = pattern.search(config_text)
                hit = (match is None) if requires_absence else (match is not None)
                if not hit:
                    continue

                # Pull the matching line (or, for absence checks, leave empty)
                # for the evidence body so the operator can see context.
                evidence_line = ""
                if match is not None:
                    line_start = config_text.rfind("\n", 0, match.start()) + 1
                    line_end = config_text.find("\n", match.end())
                    if line_end == -1:
                        line_end = len(config_text)
                    # Redact the matched line so credentials/community
                    # strings don't leak into the findings table.
                    evidence_line = redact_value(
                        config_text[line_start:line_end].strip()
                    )

                findings.append(Finding(
                    rule_id=f"{self.rule_id}.{suffix}",
                    category=self.category,
                    severity=severity,
                    title=title,
                    detail=(
                        f"{host.get('hostname', '')}: {title.lower()}."
                        + (f" Example: `{evidence_line}`" if evidence_line else "")
                    ),
                    host_id=host_id,
                    cis_control=self.cis_control,
                    evidence={
                        "hostname": host.get("hostname", ""),
                        "match_line": evidence_line,
                    },
                ))
        return findings


# Rule registry. New rule classes are appended here once their
# collectors land.
_RULE_REGISTRY: list[type[Rule]] = [
    ConfigDriftRule,
    PortHygieneRule,
    VlanConsistencyRule,
    SecurityPostureRule,
]


# ── Orchestrator ────────────────────────────────────────────────────────────

async def _persist_finding(run_id: int, finding: Finding) -> None:
    """Insert one finding row."""
    conn = await db.get_db()
    try:
        await conn.execute(
            """INSERT INTO audit_findings
               (run_id, host_id, rule_id, category, severity, cis_control,
                title, detail, evidence_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                finding.host_id,
                finding.rule_id,
                finding.category,
                finding.severity,
                finding.cis_control,
                finding.title,
                finding.detail,
                json.dumps(finding.evidence, default=str),
            ),
        )
        await conn.commit()
    finally:
        await conn.close()


async def _create_run(trigger: str) -> int:
    conn = await db.get_db()
    try:
        cursor = await conn.execute(
            """INSERT INTO audit_runs (status, trigger)
               VALUES ('running', ?)""",
            (trigger,),
        )
        await conn.commit()
        return int(cursor.lastrowid)
    finally:
        await conn.close()


async def _finalize_run(
    run_id: int,
    status: str,
    host_count: int,
    severity_counts: dict[str, int],
    summary: dict,
    error_text: str = "",
) -> None:
    conn = await db.get_db()
    try:
        await conn.execute(
            """UPDATE audit_runs SET
                 status = ?,
                 finished_at = datetime('now'),
                 host_count = ?,
                 findings_total = ?,
                 findings_critical = ?,
                 findings_high = ?,
                 findings_medium = ?,
                 findings_low = ?,
                 findings_info = ?,
                 summary_json = ?,
                 error_text = ?
               WHERE id = ?""",
            (
                status,
                host_count,
                sum(severity_counts.values()),
                severity_counts.get("critical", 0),
                severity_counts.get("high", 0),
                severity_counts.get("medium", 0),
                severity_counts.get("low", 0),
                severity_counts.get("info", 0),
                json.dumps(summary, default=str),
                error_text,
                run_id,
            ),
        )
        await conn.commit()
    finally:
        await conn.close()


async def run_audit(trigger: str = "manual") -> int:
    """Execute one full audit run end-to-end. Returns the run_id.

    Each rule's exceptions are caught individually so one broken rule
    doesn't tank the whole run -- it lands a finding instead and the
    run continues.
    """
    run_id = await _create_run(trigger)
    severity_counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    rules_executed: list[str] = []
    rules_failed: dict[str, str] = {}

    try:
        hosts = await db.get_all_hosts()
        ctx = AuditContext(run_id=run_id, hosts=hosts)

        for rule_cls in _RULE_REGISTRY:
            rule = rule_cls()
            try:
                findings = await rule.evaluate(ctx)
                rules_executed.append(rule.rule_id)
                for f in findings:
                    severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
                    await _persist_finding(run_id, f)
            except Exception as exc:
                LOGGER.warning(
                    "audit rule %s failed: %s",
                    rule.rule_id,
                    redact_value(str(exc)),
                )
                increment_metric("audit.rule.failed")
                rules_failed[rule.rule_id] = str(exc)[:500]

        summary = {
            "rules_executed": rules_executed,
            "rules_failed": rules_failed,
            "trigger": trigger,
        }
        await _finalize_run(
            run_id,
            status="success" if not rules_failed else "partial",
            host_count=len(hosts),
            severity_counts=severity_counts,
            summary=summary,
        )
        increment_metric("audit.run.completed")
        return run_id

    except Exception as exc:
        LOGGER.error("audit run %d failed: %s", run_id, exc, exc_info=True)
        increment_metric("audit.run.failed")
        await _finalize_run(
            run_id,
            status="failed",
            host_count=0,
            severity_counts=severity_counts,
            summary={"rules_executed": rules_executed, "rules_failed": rules_failed},
            error_text=str(exc)[:1000],
        )
        return run_id


# ── Background loop ─────────────────────────────────────────────────────────

async def _audit_run_loop() -> None:
    """Background polling loop for on-demand / scheduled audit runs.

    v1 only handles the on-demand queue (rows inserted with status
    ``queued`` by the API). Cron-style scheduling reuses the existing
    report scheduler pattern but is wired in a follow-up PR alongside
    the schedule UI.
    """
    while True:
        try:
            await asyncio.sleep(AUDIT_POLL_SECONDS)
            queued = await _claim_queued_run()
            if queued is not None:
                LOGGER.info("audit: starting queued run id=%d", queued)
                # Re-run using existing run row instead of creating a new one.
                await _execute_existing_run(queued, trigger="queued")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("audit loop failure: %s", redact_value(str(exc)))
            increment_metric("audit.loop.failed")
            await asyncio.sleep(AUDIT_POLL_SECONDS)


async def _claim_queued_run() -> int | None:
    """Atomically grab the oldest queued audit run, transition to running."""
    conn = await db.get_db()
    try:
        cursor = await conn.execute(
            "SELECT id FROM audit_runs WHERE status = 'queued' "
            "ORDER BY id ASC LIMIT 1"
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        run_id = int(row[0])
        await conn.execute(
            "UPDATE audit_runs SET status = 'running', started_at = datetime('now') "
            "WHERE id = ? AND status = 'queued'",
            (run_id,),
        )
        await conn.commit()
        return run_id
    finally:
        await conn.close()


async def _execute_existing_run(run_id: int, trigger: str) -> None:
    """Run rules against an audit_runs row that already exists."""
    severity_counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    rules_executed: list[str] = []
    rules_failed: dict[str, str] = {}
    try:
        hosts = await db.get_all_hosts()
        ctx = AuditContext(run_id=run_id, hosts=hosts)
        for rule_cls in _RULE_REGISTRY:
            rule = rule_cls()
            try:
                findings = await rule.evaluate(ctx)
                rules_executed.append(rule.rule_id)
                for f in findings:
                    severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
                    await _persist_finding(run_id, f)
            except Exception as exc:
                LOGGER.warning(
                    "audit rule %s failed in run %d: %s",
                    rule.rule_id, run_id, redact_value(str(exc)),
                )
                rules_failed[rule.rule_id] = str(exc)[:500]
        await _finalize_run(
            run_id,
            status="success" if not rules_failed else "partial",
            host_count=len(hosts),
            severity_counts=severity_counts,
            summary={
                "rules_executed": rules_executed,
                "rules_failed": rules_failed,
                "trigger": trigger,
            },
        )
    except Exception as exc:
        LOGGER.error("audit run %d failed: %s", run_id, exc, exc_info=True)
        await _finalize_run(
            run_id,
            status="failed",
            host_count=0,
            severity_counts=severity_counts,
            summary={"rules_executed": rules_executed, "rules_failed": rules_failed},
            error_text=str(exc)[:1000],
        )


# ── API endpoints ───────────────────────────────────────────────────────────
#
# Auth is enforced at include_router level in app.py (Depends(require_auth)
# + feature gate), matching the reporting / mac_tracking pattern.


@router.post("/api/audit/runs", status_code=201)
async def trigger_audit_run():
    """Trigger an audit run synchronously and return the resulting row.

    Runs in-process. For very large fleets this should be flipped to a
    queued execution via the background loop, but for v1 sync keeps the
    UX simple ("click button -> see result").
    """
    run_id = await run_audit(trigger="manual")
    return await get_audit_run_detail(run_id)


@router.get("/api/audit/runs")
async def list_audit_runs(
    limit: int = Query(default=50, ge=1, le=500),
):
    conn = await db.get_db()
    try:
        cursor = await conn.execute(
            """SELECT id, status, trigger, started_at, finished_at, host_count,
                      findings_total, findings_critical, findings_high,
                      findings_medium, findings_low, findings_info
               FROM audit_runs
               ORDER BY id DESC
               LIMIT ?""",
            (limit,),
        )
        rows = await cursor.fetchall()
        cols = [
            "id", "status", "trigger", "started_at", "finished_at", "host_count",
            "findings_total", "findings_critical", "findings_high",
            "findings_medium", "findings_low", "findings_info",
        ]
        return {"runs": [dict(zip(cols, r)) for r in rows]}
    finally:
        await conn.close()


@router.get("/api/audit/runs/{run_id}")
async def get_audit_run_detail(run_id: int):
    conn = await db.get_db()
    try:
        cursor = await conn.execute(
            "SELECT * FROM audit_runs WHERE id = ?", (run_id,)
        )
        row = await cursor.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="audit run not found")
        # column names from cursor.description
        cols = [d[0] for d in cursor.description]
        run = dict(zip(cols, row))
        # Parse summary_json if present
        try:
            run["summary"] = json.loads(run.get("summary_json") or "{}")
        except Exception:
            run["summary"] = {}
        return run
    finally:
        await conn.close()


@router.get("/api/audit/runs/{run_id}/findings")
async def list_audit_findings(
    run_id: int,
    severity: str | None = Query(default=None),
    host_id: int | None = Query(default=None),
):
    conn = await db.get_db()
    try:
        clauses = ["run_id = ?"]
        params: list = [run_id]
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if host_id is not None:
            clauses.append("host_id = ?")
            params.append(host_id)
        sql = (
            "SELECT id, run_id, host_id, rule_id, category, severity, "
            "cis_control, title, detail, evidence_json, created_at "
            "FROM audit_findings WHERE " + " AND ".join(clauses) +
            " ORDER BY CASE severity "
            "  WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "  WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id ASC"
        )
        cursor = await conn.execute(sql, tuple(params))
        rows = await cursor.fetchall()
        cols = [d[0] for d in cursor.description]
        findings = []
        for r in rows:
            f = dict(zip(cols, r))
            try:
                f["evidence"] = json.loads(f.pop("evidence_json") or "{}")
            except Exception:
                f["evidence"] = {}
            findings.append(f)
        return {"findings": findings}
    finally:
        await conn.close()


# ── Per-host read endpoints (powers topology NodeDetails tabs) ──────────────
#
# `interface_inventory` and `vlan_definitions` are written by the audit
# collector (folded into the topology discovery loop). The data is general-
# purpose -- exposing it via thin GETs lets the topology view's NodeDetails
# pane render the same data without joining through a rule run.

@router.get("/api/hosts/{host_id}/interface-inventory")
async def list_host_interface_inventory(host_id: int):
    rows = await db.get_interface_inventory_for_host(host_id)
    return {"host_id": host_id, "interfaces": rows}


@router.get("/api/hosts/{host_id}/vlans")
async def list_host_vlans(host_id: int):
    rows = await db.get_vlan_definitions_for_host(host_id)
    return {"host_id": host_id, "vlans": rows}


@router.get("/api/hosts/{host_id}/audit-findings")
async def list_host_audit_findings(host_id: int, limit: int = Query(default=50, le=500)):
    """Latest findings across all runs for one host (most recent first).

    Powers the NodeDetails Audit tab so the topology pane can surface
    every open issue for a device without needing to know a run_id.
    """
    conn = await db.get_db()
    try:
        cursor = await conn.execute(
            "SELECT id, run_id, host_id, rule_id, category, severity, "
            "cis_control, title, detail, evidence_json, created_at "
            "FROM audit_findings WHERE host_id = ? "
            "ORDER BY id DESC LIMIT ?",
            (host_id, limit),
        )
        rows = await cursor.fetchall()
        cols = [d[0] for d in cursor.description]
        findings = []
        for r in rows:
            f = dict(zip(cols, r))
            try:
                f["evidence"] = json.loads(f.pop("evidence_json") or "{}")
            except Exception:
                f["evidence"] = {}
            findings.append(f)
        return {"host_id": host_id, "findings": findings}
    finally:
        await conn.close()


@router.get("/api/topology/search/hosts-by-vlan")
async def search_hosts_by_vlan(vlan_id: int = Query(..., ge=1, le=4094)):
    """Return every host that carries a given VLAN, with how it carries it.

    Powers the topology search panel's VLAN-highlight mode. A host is
    considered to "carry" a VLAN if any of:
      * `vlan_definitions` has a row for that vlan_id on the host
      * any `interface_inventory` row has `access_vlan = vlan_id`
      * any `interface_inventory.trunk_vlans` CSV contains the vlan_id

    The same host can appear in multiple buckets; the response collapses
    them into one row per host with a `roles` list (definition/access/trunk).
    """
    conn = await db.get_db()
    try:
        roles: dict[int, dict] = {}

        cursor = await conn.execute(
            "SELECT v.host_id, v.name, h.hostname "
            "FROM vlan_definitions v LEFT JOIN hosts h ON h.id = v.host_id "
            "WHERE v.vlan_id = ?",
            (vlan_id,),
        )
        for row in await cursor.fetchall():
            hid = row[0]
            entry = roles.setdefault(
                hid, {"host_id": hid, "hostname": row[2], "roles": [], "ports": []}
            )
            if "definition" not in entry["roles"]:
                entry["roles"].append("definition")
            if row[1]:
                entry["vlan_name"] = row[1]

        cursor = await conn.execute(
            "SELECT i.host_id, i.name, h.hostname "
            "FROM interface_inventory i LEFT JOIN hosts h ON h.id = i.host_id "
            "WHERE i.access_vlan = ?",
            (vlan_id,),
        )
        for row in await cursor.fetchall():
            hid = row[0]
            entry = roles.setdefault(
                hid, {"host_id": hid, "hostname": row[2], "roles": [], "ports": []}
            )
            if "access" not in entry["roles"]:
                entry["roles"].append("access")
            entry["ports"].append({"name": row[1], "kind": "access"})

        cursor = await conn.execute(
            "SELECT i.host_id, i.name, i.trunk_vlans, h.hostname "
            "FROM interface_inventory i LEFT JOIN hosts h ON h.id = i.host_id "
            "WHERE i.trunk_vlans IS NOT NULL AND i.trunk_vlans != ''",
        )
        target = str(vlan_id)
        for row in await cursor.fetchall():
            csv_val = row[2] or ""
            members = {p.strip() for p in csv_val.split(",") if p.strip()}
            if target not in members:
                continue
            hid = row[0]
            entry = roles.setdefault(
                hid, {"host_id": hid, "hostname": row[3], "roles": [], "ports": []}
            )
            if "trunk" not in entry["roles"]:
                entry["roles"].append("trunk")
            entry["ports"].append({"name": row[1], "kind": "trunk"})

        return {"vlan_id": vlan_id, "hosts": list(roles.values())}
    finally:
        await conn.close()
