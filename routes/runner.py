"""
runner.py — Base playbook runner and registry.

Every automation script subclasses BasePlaybook and registers itself.
The runner executes playbooks as async background tasks, yielding
LogEvent objects that get stored in the DB and streamed via WebSocket.
"""

import traceback
from collections.abc import AsyncGenerator
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
        filename     — the script filename used for registration
        display_name — human-readable name
        description  — what the playbook does
        tags         — list of keyword tags

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

    async def run(
        self,
        hosts: list[dict],
        credentials: dict,
        template_commands: list[str] | None = None,
        dry_run: bool = True,
    ) -> AsyncGenerator[LogEvent, None]:
        raise NotImplementedError("Subclasses must implement run()")
        yield  # make it a generator

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
) -> PlaybookResult:
    """
    Run a playbook and collect results.

    event_callback is an async callable(LogEvent) for real-time streaming.
    """
    pb = playbook_cls()
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
