"""
runner.py - Base playbook runner and registry.

Every automation script subclasses BasePlaybook and registers itself.
The runner executes playbooks as async background tasks, yielding
LogEvent objects that get stored in the DB and streamed via WebSocket.
"""

import asyncio
import os
import traceback
from collections.abc import AsyncGenerator, Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime

# ── Registry ─────────────────────────────────────────────────────────────────

_PLAYBOOK_REGISTRY: dict[str, type] = {}


def register_playbook(cls):
    """Decorator: register a BasePlaybook subclass by its filename."""
    _PLAYBOOK_REGISTRY[cls.filename] = cls
    return cls


def get_playbook_class(filename: str):
    return _PLAYBOOK_REGISTRY.get(filename)


def list_registered_playbooks() -> list[dict]:
    return [
        {
            "filename": cls.filename,
            "name": cls.display_name,
            "description": cls.description,
            "tags": cls.tags,
            "requires_template": cls.requires_template,
            "parameters_schema": cls.parameters_schema,
        }
        for cls in _PLAYBOOK_REGISTRY.values()
    ]


# ── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class LogEvent:
    level: str          # info, success, error, warn, cmd, dim, sep
    message: str
    host: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HostResult:
    host: str
    status: str         # ok, failed, skipped
    message: str = ""


@dataclass
class PlaybookResult:
    status: str         # success, failed
    hosts_ok: int = 0
    hosts_failed: int = 0
    hosts_skipped: int = 0


# ── Base class ───────────────────────────────────────────────────────────────

class BasePlaybook:
    """
    Abstract base for all automation playbooks.

    Subclasses must set:
        filename     - the script filename used for registration
        display_name - human-readable name
        description  - what the playbook does
        tags         - list of keyword tags

    Subclasses must implement:
        async def run(self, hosts, credentials, template_commands, dry_run)
            -> AsyncGenerator[LogEvent, None]

    The run() method is an async generator that yields LogEvent objects
    as the script executes. This allows real-time streaming to the frontend.
    """

    filename: str = ""
    display_name: str = ""
    description: str = ""
    tags: list[str] = []

    # Set to True to indicate this playbook needs a template
    requires_template: bool = False

    # Declarative schema for per-job parameters. Each entry is rendered as a
    # form field in the job-launch modal; the entered values are stored on the
    # job row and assigned to ``self.parameters`` before ``run()`` executes.
    # Shape: [{"name": "collector_ip", "type": "string", "label": "Collector IP",
    #          "required": True, "default": "", "help": "..."}].
    # Supported types: "string", "int", "bool", "list" (comma-separated input).
    parameters_schema: list[dict] = []

    # Populated by the executor right before run() - never read directly here.
    parameters: dict | None = None

    # Per-device_type resolved template command bodies, keyed by the
    # host's Netmiko device_type string.  Populated by the executor when
    # the job's template has vendor-specific variants (Phase 12 of the
    # driver framework).  Empty for legacy single-body templates; in
    # that case playbooks use the flat ``template_commands`` argument as
    # before.  Vendor-aware playbooks (e.g. snmpv3_configurator) consult
    # this map so a mixed-vendor inventory group runs the right command
    # body per host without the operator picking N templates.
    template_by_device_type: dict[str, list[str]] | None = None

    # Maximum number of hosts this playbook processes at once. Subclasses can
    # override this for especially sensitive workflows; otherwise the process
    # wide APP_PLAYBOOK_HOST_CONCURRENCY setting is used.
    host_concurrency: int | None = None

    def commands_for_host(
        self, host: dict, template_commands: list[str] | None
    ) -> list[str] | None:
        """Return the template body to push to a single host.

        Prefers the vendor-specific body resolved into
        ``template_by_device_type`` for this host's device_type; falls
        back to the flat ``template_commands`` (the generic body / the
        legacy single-template path) so playbooks that don't care about
        per-vendor templates keep working unchanged.
        """
        by_dt = self.template_by_device_type or {}
        dt = host.get("device_type") or ""
        if dt in by_dt:
            return by_dt[dt]
        # The empty-string key is the generic body when at least one
        # vendor variant exists but this host's vendor isn't one of them.
        if "" in by_dt:
            return by_dt[""]
        return template_commands

    async def run(
        self,
        hosts: list[dict],
        credentials: dict,
        template_commands: list[str] | None = None,
        dry_run: bool = True,
    ) -> AsyncGenerator[LogEvent]:
        raise NotImplementedError("Subclasses must implement run()")
        yield  # make it a generator

    async def run_hosts_concurrently(
        self,
        hosts: list[dict],
        worker: Callable[[dict], AsyncGenerator[LogEvent]],
    ) -> AsyncGenerator[LogEvent]:
        """Run a per-host async-generator worker with bounded concurrency.

        Events from different hosts may interleave, but each individual host's
        event order is preserved. A worker failure cancels the remaining host
        tasks and propagates so the job is marked failed by the executor.
        """
        if not hosts:
            return

        configured = self.host_concurrency
        if configured is None:
            try:
                configured = int(os.getenv("APP_PLAYBOOK_HOST_CONCURRENCY", "5"))
            except ValueError:
                configured = 5
        limit = max(1, configured)

        semaphore = asyncio.Semaphore(limit)
        queue: asyncio.Queue[tuple[LogEvent | None, BaseException | None]] = (
            asyncio.Queue()
        )

        async def run_one(host: dict) -> None:
            try:
                async with semaphore:
                    async for event in worker(host):
                        await queue.put((event, None))
            except BaseException as exc:
                await queue.put((None, exc))
            finally:
                await queue.put((None, None))

        tasks = [asyncio.create_task(run_one(host)) for host in hosts]
        remaining = len(tasks)
        try:
            while remaining:
                event, error = await queue.get()
                if event is not None:
                    yield event
                elif error is not None:
                    raise error
                else:
                    remaining -= 1
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    # ── Convenience log helpers ──────────────────────────────────────────

    def log_info(self, msg: str, host: str = "") -> LogEvent:
        return LogEvent(level="info", message=msg, host=host)

    def log_success(self, msg: str, host: str = "") -> LogEvent:
        return LogEvent(level="success", message=msg, host=host)

    def log_error(self, msg: str, host: str = "") -> LogEvent:
        return LogEvent(level="error", message=msg, host=host)

    def log_warn(self, msg: str, host: str = "") -> LogEvent:
        return LogEvent(level="warn", message=msg, host=host)

    def log_sep(self) -> LogEvent:
        return LogEvent(level="sep", message="=" * 60)


# ── Executor ─────────────────────────────────────────────────────────────────

async def execute_playbook(
    playbook_cls: type,
    hosts: list[dict],
    credentials: dict,
    template_commands: list[str] | None = None,
    dry_run: bool = True,
    event_callback=None,
    parameters: dict | None = None,
    template_by_device_type: dict[str, list[str]] | None = None,
) -> PlaybookResult:
    """
    Run a playbook and collect results.

    event_callback is an async callable(LogEvent) for real-time streaming.
    """
    pb = playbook_cls()
    pb.parameters = parameters or {}
    pb.template_by_device_type = template_by_device_type or {}
    hosts_ok = 0
    hosts_failed = 0
    hosts_skipped = 0
    status = "success"

    try:
        async for event in pb.run(hosts, credentials, template_commands, dry_run):
            if event_callback:
                await event_callback(event)

            # Track host-level results from event messages
            if event.level == "success" and "Finished processing" in event.message:
                hosts_ok += 1
            elif event.level == "error" and event.host:
                hosts_failed += 1

    except Exception as e:
        error_event = LogEvent(
            level="error",
            message=f"Playbook execution failed: {e}\n{traceback.format_exc()}"
        )
        if event_callback:
            await event_callback(error_event)
        status = "failed"

    if hosts_failed > 0 and hosts_ok == 0:
        status = "failed"

    return PlaybookResult(
        status=status,
        hosts_ok=hosts_ok,
        hosts_failed=hosts_failed,
        hosts_skipped=hosts_skipped,
    )
