"""The ChatOps command catalogue.

Each command names the feature keys its caller needs (beyond ``chatops``)
and whether it changes anything (``write``). Write commands are off on a
bot until an admin adds them to its allowed commands, and ``run`` launches
only the job presets an admin approved.

The read commands reuse the MCP query tools (``netcontrol.mcp.tools``):
the same host resolution, the same queries, the same secret masking. The
IPAM lookup reuses the IPAM routes' best-subnet logic, and ``run`` the job
clone helpers of ``netcontrol.routes.jobs``.
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import routes.database as db

from netcontrol.chatops.replies import Action, Reply, error
from netcontrol.mcp import redact, registry
from netcontrol.mcp.auth import CATEGORIES, McpContext
from netcontrol.routes.shared import _audit

FEATURE = "chatops"
SEVERITIES = ("critical", "warning", "info")
PROTOCOLS = ("tcp", "udp", "icmp")
TOOL_TIMEOUT_SECONDS = 25.0
MAX_ALERTS = 10
MAX_JOBS = 25


class CommandError(Exception):
    """A failure whose message is safe to show in chat."""


@dataclass(frozen=True)
class ChatUser:
    """Who sent a command: the chat identity and the Plexus user it maps to."""

    platform: str
    chat_user_id: str
    chat_user_name: str = ""
    user: dict | None = None
    features: frozenset[str] = frozenset()
    object_scoped: bool = False

    @property
    def mapped(self) -> bool:
        return self.user is not None

    @property
    def username(self) -> str:
        return str((self.user or {}).get("username") or "")

    @property
    def is_admin(self) -> bool:
        return (self.user or {}).get("role") == "admin"

    def has(self, feature: str) -> bool:
        return self.is_admin or feature in self.features


@dataclass
class Invocation:
    user: ChatUser
    allowed_commands: frozenset[str] = frozenset()
    channel: dict[str, Any] = field(default_factory=dict)

    def can(self, name: str) -> bool:
        command = get(name)
        return command is not None and refusal(command, self) is None


Handler = Callable[[Invocation, list[str]], Awaitable[Reply]]


@dataclass(frozen=True)
class Command:
    name: str
    usage: str
    summary: str
    handler: Handler
    features: tuple[str, ...] = ()
    write: bool = False
    aliases: tuple[str, ...] = ()


_COMMANDS: dict[str, Command] = {}
_ALIASES: dict[str, str] = {}


def register(command: Command) -> Command:
    _COMMANDS[command.name] = command
    for alias in command.aliases:
        _ALIASES[alias] = command.name
    return command


def get(name: str) -> Command | None:
    key = (name or "").strip().lower()
    return _COMMANDS.get(_ALIASES.get(key, key))


def catalogue() -> list[Command]:
    return list(_COMMANDS.values())


def default_allowed() -> list[str]:
    """What a new bot accepts: every read command."""
    return [c.name for c in catalogue() if not c.write and c.name != "help"]


def refusal(command: Command, inv: Invocation) -> str | None:
    """Why ``inv``'s caller may not run ``command``; ``None`` when allowed."""
    if command.name == "help":
        return None
    if command.name not in inv.allowed_commands:
        return f"The {command.name} command is not enabled on this bot."
    user = inv.user
    if not user.mapped:
        return "unmapped"
    if user.object_scoped:
        return "Your Plexus account is limited to selected inventory groups, which ChatOps does not support."
    if not user.has(FEATURE):
        return "Your Plexus account does not have the ChatOps feature."
    missing = [f for f in command.features if not user.has(f)]
    if missing:
        return f"Your Plexus account needs the {', '.join(missing)} feature for {command.name}."
    return None


# ── Shared helpers ───────────────────────────────────────────────────────────


def _mcp_ctx(user: ChatUser) -> McpContext:
    owner = user.user or {}
    return McpContext(
        token_id=0,
        token_name=f"chatops:{user.platform}",
        owner_id=int(owner.get("id") or 0),
        owner_username=user.username,
        owner_is_admin=user.is_admin,
        categories=frozenset(CATEGORIES),
        features=user.features,
        object_scoped=user.object_scoped,
    )


async def run_tool(user: ChatUser, name: str, args: dict[str, Any]) -> Any:
    """Run one MCP query tool as ``user``: the tool's own argument schema,
    its handler and the MCP secret masking. Raises ``CommandError``."""
    from netcontrol.mcp.dispatch import _argument_error

    registry.load_tools()
    tool = registry.get_tool(name)
    if tool is None:  # pragma: no cover - the tools are part of Plexus
        raise CommandError("That query is not available.")
    problem = _argument_error(tool, args)
    if problem:
        raise CommandError(problem.replace(f"Invalid arguments for {name}: ", "Invalid arguments: "))
    try:
        result = await asyncio.wait_for(tool.handler(_mcp_ctx(user), args), TOOL_TIMEOUT_SECONDS)
    except registry.ToolError as exc:
        message = str(exc).replace(" Try search_hosts.", "").replace("as the host argument", "instead")
        raise CommandError(redact.redact_config_text(message) or "The query could not answer.") from None
    except TimeoutError:
        raise CommandError("The query took too long. Narrow it and try again.") from None
    return redact.redact_result(result)


def _need(args: list[str], count: int, usage: str) -> None:
    if len(args) < count:
        raise CommandError(f"Usage: /plexus {usage}")


def _text(value: Any, fallback: str = "-") -> str:
    text = str(value).strip() if value is not None else ""
    return text or fallback


def _fields(pairs: list[tuple[str, Any]]) -> list[tuple[str, str]]:
    return [(k, str(v)) for k, v in pairs if v not in (None, "", [])]


def _no_data(result: Any) -> str | None:
    if isinstance(result, dict) and result.get("no_data"):
        return str(result.get("message") or "No data collected yet.")
    return None


# ── help ─────────────────────────────────────────────────────────────────────


async def help_reply(inv: Invocation, args: list[str]) -> Reply:
    user = inv.user
    if args:
        command = get(args[0])
        if command is None:
            return error(f"Unknown command: {args[0]}", "Type /plexus help for the list.")
        return Reply(
            title=f"/plexus {command.usage}",
            text=command.summary,
            note="Changes something in Plexus." if command.write else "",
        )
    if not user.mapped:
        return Reply(
            title="Plexus ChatOps",
            text=(
                "Your chat account is not linked to a Plexus user, so no commands are available. "
                f"Ask a Plexus admin to map {user.platform} user {user.chat_user_id} under Settings > ChatOps."
            ),
        )
    usable = [c for c in catalogue() if c.name != "help" and refusal(c, inv) is None]
    items = [f"/plexus {c.usage} - {c.summary}" for c in usable]
    return Reply(
        title="Plexus ChatOps commands",
        text="" if usable else "No commands are available to your account on this bot.",
        items=items,
        note=f"Signed in to Plexus as {user.username}. /plexus help <command> shows one command.",
    )


# ── Inventory and status ─────────────────────────────────────────────────────


async def _device(inv: Invocation, args: list[str]) -> Reply:
    _need(args, 1, "device <name|address|id>")
    host = await run_tool(inv.user, "get_host", {"host": " ".join(args)})
    return Reply(
        title=f"{host.get('hostname')} ({host.get('ip_address')})",
        fields=_fields(
            [
                ("Group", host.get("group")),
                ("Platform", host.get("device_type")),
                ("Model", host.get("model")),
                ("Software", host.get("software_version")),
                ("Serial", host.get("serial_number")),
                ("Status", host.get("status")),
                ("Last seen", host.get("last_seen")),
                ("VRF", host.get("vrf_name")),
                ("Id", host.get("id")),
            ]
        ),
        items=[f"Also owns {a}" for a in host.get("alias_addresses") or []],
    )


def _speed(mbps: Any) -> str:
    try:
        value = int(mbps or 0)
    except TypeError, ValueError:
        return ""
    if value <= 0:
        return ""
    return f"{value // 1000}G" if value >= 1000 and value % 1000 == 0 else f"{value}M"


async def _interfaces(inv: Invocation, args: list[str]) -> Reply:
    _need(args, 1, "interfaces <device> [name filter]")
    query: dict[str, Any] = {"host": args[0]}
    if len(args) > 1:
        query["name"] = " ".join(args[1:])
    data = await run_tool(inv.user, "get_interfaces", query)
    missing = _no_data(data)
    if missing:
        return Reply(title=f"Interfaces of {args[0]}", text=missing)
    rows = data.get("interfaces") or []
    up = sum(1 for r in rows if str(r.get("oper_state") or "").lower() == "up")
    items = []
    for row in rows:
        parts = [
            _text(row.get("name")),
            f"{_text(row.get('admin_state'), '?')}/{_text(row.get('oper_state'), '?')}",
            _speed(row.get("speed_mbps")),
            str(row.get("description") or ""),
        ]
        items.append("  ".join(p for p in parts if p))
    host = data.get("host") or {}
    return Reply(
        title=f"Interfaces of {host.get('hostname') or args[0]}",
        fields=[("Interfaces", str(len(rows))), ("Up", str(up)), ("Not up", str(len(rows) - up))],
        items=items,
        note="admin/operational state",
    )


def _metric(summary: dict[str, Any], key: str, unit: str) -> str:
    value = (summary.get(key) or {}).get("avg")
    return f"{value}{unit} avg" if value is not None else ""


async def _status(inv: Invocation, args: list[str]) -> Reply:
    _need(args, 1, "status <device>")
    data = await run_tool(inv.user, "get_device_health", {"host": " ".join(args)})
    missing = _no_data(data)
    if missing:
        return Reply(title=f"Status of {' '.join(args)}", text=missing)
    host = data.get("host") or {}
    latest = data.get("latest_poll") or {}
    summary = data.get("summary") or {}
    return Reply(
        title=f"Status of {host.get('hostname')} ({host.get('ip_address')})",
        fields=_fields(
            [
                ("Status", data.get("status")),
                ("Last poll", latest.get("polled_at")),
                ("Last poll result", latest.get("poll_status")),
                (
                    "CPU",
                    latest.get("cpu_percent") if latest.get("cpu_percent") is None else f"{latest['cpu_percent']}%",
                ),
                (
                    "Memory",
                    latest.get("memory_percent")
                    if latest.get("memory_percent") is None
                    else f"{latest['memory_percent']}%",
                ),
                ("Response time", _metric(summary, "response_time_ms", " ms")),
                ("Packet loss", _metric(summary, "packet_loss_pct", "%")),
                (f"Failed polls ({data.get('window_hours')}h)", f"{data.get('failed_polls_in_window', 0)}"),
            ]
        ),
    )


# ── Alerts ───────────────────────────────────────────────────────────────────


def _alert_line(row: dict[str, Any]) -> str:
    severity = str(row.get("severity") or "").upper()
    if row.get("source") == "meraki":
        where = row.get("device") or row.get("network") or "Meraki"
        return f"[{severity}] {where}: {row.get('message') or ''} (Meraki, since {row.get('started_at') or '?'})"
    host = (row.get("host") or {}).get("hostname") or "?"
    return f"#{row.get('id')} [{severity}] {host}: {row.get('message') or ''} (since {row.get('started_at') or '?'})"


async def _alerts(inv: Invocation, args: list[str]) -> Reply:
    query: dict[str, Any] = {"limit": MAX_ALERTS}
    rest = list(args)
    if rest and rest[-1].lower() in SEVERITIES:
        query["severity"] = rest.pop().lower()
    if rest:
        query["host"] = " ".join(rest)
    data = await run_tool(inv.user, "list_alerts", query)
    missing = _no_data(data)
    if missing:
        return Reply(title="Active alerts", text=missing)
    rows = data.get("items") or []
    total = int(data.get("total") or len(rows))
    actions = []
    if inv.can("ack"):
        actions = [
            Action(f"Acknowledge #{r['id']}", f"ack {r['id']}")
            for r in rows
            if r.get("source") == "inventory" and r.get("id") is not None
        ][:5]
    return Reply(
        title=f"Active alerts ({total})",
        text="" if rows else "No active alerts.",
        items=[_alert_line(r) for r in rows],
        note=f"Showing the newest {len(rows)}." if total > len(rows) else "",
        actions=actions,
    )


async def _ack(inv: Invocation, args: list[str]) -> Reply:
    _need(args, 1, "ack <alert id>")
    try:
        alert_id = int(args[0].lstrip("#"))
    except ValueError:
        raise CommandError("The alert id is a number, for example /plexus ack 42.") from None
    alert = await db.get_monitoring_alert(alert_id)
    if not alert:
        raise CommandError(f"There is no alert #{alert_id}.")
    host = alert.get("hostname") or f"host {alert.get('host_id')}"
    if alert.get("acknowledged"):
        return Reply(
            title=f"Alert #{alert_id} is already acknowledged",
            fields=_fields([("By", alert.get("acknowledged_by")), ("At", alert.get("acknowledged_at"))]),
        )
    username = inv.user.username
    await db.acknowledge_monitoring_alert(alert_id, username)
    await _audit(
        "monitoring",
        "alert.acknowledged",
        user=username,
        detail=f"alert_id={alert_id} via=chatops:{inv.user.platform}",
    )
    return Reply(
        title=f"Alert #{alert_id} acknowledged by {username}",
        text=f"{host}: {alert.get('message') or ''}",
        public=True,
    )


# ── IPAM and path trace ──────────────────────────────────────────────────────


async def _ip(inv: Invocation, args: list[str]) -> Reply:
    _need(args, 1, "ip <address|prefix>")
    target = args[0].strip()
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            raise CommandError(f"{target} is not an IP prefix.") from None
        detail = await db.get_ipam_subnet_detail(str(network))
        summary = detail.get("summary") or {}
        prefixes = detail.get("prefixes") or []
        return Reply(
            title=f"Prefix {detail.get('subnet')}",
            fields=_fields(
                [
                    ("Usable", summary.get("usable_address_count")),
                    ("Allocated", summary.get("allocated_address_count")),
                    ("Reserved", summary.get("reserved_address_count")),
                    ("Available", summary.get("available_address_count")),
                    ("Inventory hosts", summary.get("inventory_host_count")),
                ]
            ),
            items=[
                f"{p.get('source_name') or p.get('provider')}: {p.get('description') or 'no description'}"
                + (f" (VRF {p['vrf']})" if p.get("vrf") else "")
                + (f", tenant {p['tenant_name']}" if p.get("tenant_name") else "")
                for p in prefixes
            ],
            note=("Next free: " + ", ".join((detail.get("available_preview") or [])[:5]))
            if detail.get("available_preview")
            else "",
        )
    try:
        ipaddress.ip_address(target)
    except ValueError:
        raise CommandError(f"{target} is not an IP address or prefix.") from None
    from netcontrol.routes.ipam import ipam_address_context_api

    context = await ipam_address_context_api(target, vrf=None)
    subnet = context.get("matched_subnet") or {}
    interfaces = context.get("interfaces") or []
    return Reply(
        title=f"Address {target}",
        text="" if subnet else "No IPAM subnet contains this address.",
        fields=_fields(
            [
                ("Subnet", subnet.get("subnet")),
                ("VRF", subnet.get("vrf_name")),
                ("Source", subnet.get("source")),
                (
                    "Utilization",
                    f"{subnet.get('utilization_pct')}%" if subnet.get("utilization_pct") is not None else "",
                ),
                ("Conflict", "Yes, in " + ", ".join(map(str, context.get("conflict_groups") or [])))
                if context.get("is_conflict")
                else ("Conflict", ""),
            ]
        ),
        items=[
            f"On {i.get('hostname') or i.get('host_id')} {i.get('interface_name') or i.get('interface') or ''}".strip()
            for i in interfaces
        ],
    )


def _hop_line(hop: dict[str, Any]) -> str:
    label = hop.get("label") or hop.get("name") or "?"
    ports = " -> ".join(str(p) for p in (hop.get("in"), hop.get("out")) if p)
    return f"{label} ({ports})" if ports else str(label)


async def _trace(inv: Invocation, args: list[str]) -> Reply:
    _need(args, 2, "trace <source> <destination> [tcp|udp|icmp] [port]")
    query: dict[str, Any] = {"source": args[0], "destination": args[1]}
    for extra in args[2:4]:
        if extra.lower() in PROTOCOLS:
            query["protocol"] = extra.lower()
        elif extra.isdigit():
            query["port"] = int(extra)
        else:
            raise CommandError(f"Unexpected '{extra}'. Usage: /plexus trace <source> <destination> [protocol] [port]")
    result = await run_tool(inv.user, "trace_path", query)
    request = result.get("request") or {}
    asymmetric = result.get("asymmetric") or {}
    return Reply(
        title=f"Path {args[0]} to {args[1]}",
        text=str(result.get("summary") or request.get("summary") or ""),
        fields=_fields(
            [
                ("Verdict", result.get("verdict")),
                ("Traffic", result.get("traffic")),
                ("Return path", asymmetric.get("text")),
            ]
        ),
        items=[_hop_line(h) for h in request.get("hops") or [] if isinstance(h, dict)],
        note="From stored data; nothing was sent on the network.",
    )


# ── Jobs ─────────────────────────────────────────────────────────────────────


def _job_line(job: dict[str, Any]) -> str:
    mode = "dry run" if job.get("dry_run") else "commit"
    when = job.get("finished_at") or job.get("started_at") or job.get("queued_at") or ""
    return (
        f"#{job.get('id')} {job.get('playbook_name')}: {job.get('status')} ({mode}) by {job.get('launched_by')} {when}"
    )


async def _jobs(inv: Invocation, args: list[str]) -> Reply:
    count = 10
    if args:
        try:
            count = max(1, min(MAX_JOBS, int(args[0])))
        except ValueError:
            raise CommandError("Usage: /plexus jobs [count]") from None
    rows = await db.get_all_jobs(limit=count)
    return Reply(
        title="Recent jobs",
        text="" if rows else "No jobs yet.",
        items=[_job_line(j) for j in rows],
    )


async def _job(inv: Invocation, args: list[str]) -> Reply:
    _need(args, 1, "job <job id>")
    try:
        job_id = int(args[0].lstrip("#"))
    except ValueError:
        raise CommandError("The job id is a number, for example /plexus job 12.") from None
    job = await db.get_job(job_id)
    user = inv.user
    # Same rule as GET /api/jobs/{id}: the launcher or an admin.
    if not job or (not user.is_admin and job.get("launched_by") != user.username):
        raise CommandError(f"There is no job #{job_id} you can view.")
    events = await db.get_job_events(job_id, 10000)
    tail = [str(e.get("message") or "") for e in events[-5:]]
    return Reply(
        title=f"Job #{job_id}: {job.get('playbook_name')}",
        fields=_fields(
            [
                ("Status", job.get("status")),
                ("Mode", "dry run" if job.get("dry_run") else "commit"),
                ("Launched by", job.get("launched_by")),
                ("Queued", job.get("queued_at")),
                ("Started", job.get("started_at")),
                ("Finished", job.get("finished_at")),
                (
                    "Hosts",
                    f"{job.get('hosts_ok') or 0} ok, {job.get('hosts_failed') or 0} failed, "
                    f"{job.get('hosts_skipped') or 0} skipped",
                ),
            ]
        ),
        items=[line for line in tail if line],
    )


async def _run(inv: Invocation, args: list[str]) -> Reply:
    if not args:
        presets = await db.list_chatops_job_presets(enabled_only=True)
        return Reply(
            title="Job presets",
            text=""
            if presets
            else "No job presets are approved for chat. An admin adds them under Settings > ChatOps.",
            items=[
                f"{p['name']} ({'commit' if p['commit'] else 'dry run'}): {p.get('description') or p.get('playbook_name')}"
                for p in presets
            ],
            note="/plexus run <preset> launches one.",
        )
    confirmed = len(args) > 1 and args[-1].lower() == "confirm"
    name = " ".join(args[:-1] if confirmed else args)
    preset = await db.get_chatops_job_preset_by_name(name)
    if not preset or not preset.get("enabled"):
        raise CommandError(f"There is no approved job preset named '{name}'. /plexus run lists them.")
    spec = preset["spec"]
    commit = bool(preset["commit"])
    if commit and not confirmed:
        return Reply(
            title=f"Run '{preset['name']}' with commit?",
            text="This preset changes device configuration.",
            actions=[Action("Run with commit", f"run {preset['name']} confirm", danger=True)],
            note=f"Or type /plexus run {preset['name']} confirm",
        )
    job_id = await _launch(inv.user, preset, spec, commit)
    return Reply(
        title=f"Job #{job_id} queued: {preset['name']}",
        text=f"Launched by {inv.user.username} as a {'commit' if commit else 'dry run'}.",
        actions=[Action("Job status", f"job {job_id}")] if inv.can("job") else [],
        public=True,
    )


async def _launch(user: ChatUser, preset: dict, spec: dict, commit: bool) -> int:
    """The launch checks of ``POST /api/jobs/launch`` for a stored spec, then
    queue it as ``user``."""
    from fastapi import HTTPException

    from netcontrol import job_inputs
    from netcontrol.routes.jobs import queue_job_from_spec
    from netcontrol.routes.playbooks import playbook_permissions, playbook_supports_dry_run
    from netcontrol.routes.shared import require_credential_access

    playbook = await db.get_playbook(int(spec.get("playbook_id") or 0))
    if not playbook:
        raise CommandError("The preset's playbook no longer exists.")
    owner = user.user or {}
    role = str(owner.get("role") or "")
    group_ids = await db.get_user_group_ids(int(owner.get("id") or 0))
    permissions = playbook_permissions(playbook)
    if not job_inputs.is_allowed(permissions, "run", role=role, group_ids=group_ids):
        raise CommandError(f"You are not allowed to run '{playbook['name']}'.")
    if commit and not job_inputs.is_allowed(permissions, "commit", role=role, group_ids=group_ids):
        raise CommandError(f"You may not run '{playbook['name']}' with commit.")
    if playbook.get("type") == "ansible" and not user.is_admin:
        raise CommandError("Ansible playbooks can be launched by admins only.")
    if not commit and not playbook_supports_dry_run(playbook):
        raise CommandError(f"'{playbook['name']}' has no dry-run mode.")
    from netcontrol.routes import state

    cred_id = spec.get("credential_id") or state.AUTH_CONFIG.get("default_credential_id")
    if cred_id:
        try:
            await require_credential_access(cred_id, submitter_username=user.username)
        except HTTPException:
            raise CommandError("The preset's credential is not one your Plexus account may use.") from None
    job_id = await queue_job_from_spec(spec, dry_run=not commit, launched_by=user.username)
    await _audit(
        "jobs",
        "job.launch",
        user=user.username,
        detail=(
            f"queued job {job_id} playbook='{playbook['name']}' preset='{preset['name']}' "
            f"mode={'commit' if commit else 'dry-run'} via=chatops:{user.platform}"
        ),
    )
    return job_id


register(Command("help", "help [command]", "Lists the commands you can use.", help_reply, aliases=("?",)))
register(
    Command(
        "device",
        "device <name|address|id>",
        "Shows an inventory device: platform, model, software, status and group.",
        _device,
        features=("inventory",),
        aliases=("host",),
    )
)
register(
    Command(
        "interfaces",
        "interfaces <device> [name filter]",
        "Lists a device's interfaces with admin and operational state.",
        _interfaces,
        features=("topology",),
        aliases=("int", "interface"),
    )
)
register(
    Command(
        "status",
        "status <device>",
        "Shows a device's latest poll: reachability, CPU, memory, response time.",
        _status,
        features=("monitoring",),
    )
)
register(
    Command(
        "alerts",
        "alerts [device] [critical|warning|info]",
        "Lists the newest active alerts.",
        _alerts,
        features=("monitoring",),
    )
)
register(
    Command(
        "ack",
        "ack <alert id>",
        "Acknowledges a monitoring alert.",
        _ack,
        features=("monitoring", "monitoring.write"),
        write=True,
        aliases=("acknowledge",),
    )
)
register(
    Command(
        "ip",
        "ip <address|prefix>",
        "Looks up an address or prefix in IPAM: subnet, utilisation, conflicts, interfaces.",
        _ip,
        features=("ipam",),
        aliases=("ipam", "prefix"),
    )
)
register(
    Command(
        "trace",
        "trace <source> <destination> [tcp|udp|icmp] [port]",
        "Traces the path between two addresses or devices from stored routes and rules.",
        _trace,
        features=("topology",),
        aliases=("path",),
    )
)
register(Command("jobs", "jobs [count]", "Lists the most recent jobs.", _jobs, features=("jobs",)))
register(Command("job", "job <job id>", "Shows one job's status and its last log lines.", _job, features=("jobs",)))
register(
    Command(
        "run",
        "run [preset] [confirm]",
        "Launches a job preset an admin approved for chat; without a name lists them.",
        _run,
        features=("jobs", "jobs.write"),
        write=True,
    )
)
