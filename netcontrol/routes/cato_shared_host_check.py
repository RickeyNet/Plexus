"""The Cato shared hosts vs Azure check, run server-side.

``run_shared_host_check`` runs after every stored Cato collection and Azure
discovery (``netcontrol.routes.meraki_topology``, next to the egress check)
and on demand (``POST /api/monitoring/cato-shared-hosts/run``). It
evaluates the Shared Hosts rules of the latest snapshot of every Cato
account against the Azure reachability engine
(``netcontrol.integrations.cato.shared_host_check``), stores the findings
in the egress check's table under ``check_name`` ``shared_host``
(``routes.db.cato_egress``) and alerts on the warnings through the loop the
egress check uses (``cato_egress_check.run_check``): alert type
``cato_shared_host``, a monitoring alert when a finding's address is an
inventory host, else the notification channels, once while it stays open,
acknowledged as ``auto-resolved`` when it clears. Best-effort: a failure is
logged and never fails the collection that triggered the run.

The Cato system range the per-user tunnels go to is
``shared_host_check.DEFAULT_SYSTEM_RANGE`` unless ``PLEXUS_CATO_SYSTEM_RANGE``
names another IPv4 network (an account that changed it in the Cato
Management Application).

Object scope: as the egress check, the findings are of Cato and cloud
accounts: a caller limited to selected inventory groups sees none and
cannot run the check.
"""

from __future__ import annotations

import functools
import ipaddress
import os
from typing import Any

from fastapi import APIRouter, Query, Request

from netcontrol.integrations.cato import shared_host_check
from netcontrol.object_scope import scoped
from netcontrol.routes import cato_egress_check as base
from netcontrol.telemetry import configure_logging

router = APIRouter()
LOGGER = configure_logging("plexus.cato_shared_host")

ALERT_TYPE = "cato_shared_host"
SYSTEM_RANGE_ENV = "PLEXUS_CATO_SYSTEM_RANGE"

SHARED_HOST = base.CheckSpec(
    name="shared_host",
    alert_type=ALERT_TYPE,
    metric="cato shared hosts",
    title="Cato shared hosts",
    prefix="cato_shared_host",
    audit_action="cato_shared_host.checked",
    log_name="cato shared hosts",
    logger=LOGGER,
)


def system_range() -> str:
    """The Cato system range: ``PLEXUS_CATO_SYSTEM_RANGE`` when it is an
    IPv4 network, else the Cato default."""
    raw = os.getenv(SYSTEM_RANGE_ENV, "").strip()
    if raw:
        try:
            return str(ipaddress.IPv4Network(raw, strict=False))
        except ValueError:
            LOGGER.warning("%s=%r is not an IPv4 network; using %s", SYSTEM_RANGE_ENV, raw, _default())
    return _default()


def _default() -> str:
    return shared_host_check.DEFAULT_SYSTEM_RANGE


async def _inputs() -> tuple[list[tuple[int, dict]], list[tuple[str, Any]], set[str]]:
    return await base._inputs()


async def run_shared_host_check(trigger: str = "manual") -> dict[str, Any]:
    """Run the check, store its findings and alert on the warnings. Never
    raises: a failure is logged and reported in ``error``."""
    check = functools.partial(shared_host_check.check, system_range=system_range())
    return await base.run_check(SHARED_HOST, trigger, check, _inputs)


# ── API ─────────────────────────────────────────────────────────────────────


@router.get("/api/monitoring/cato-shared-hosts/findings")
@scoped("list")
async def list_cato_shared_host_findings_api(
    request: Request,
    include_resolved: bool = Query(default=False),
    limit: int = Query(default=1000, ge=1, le=10000),
):
    """The findings of the Cato shared hosts vs Azure check (none for a
    caller limited to selected inventory groups)."""
    return await base.list_findings(request, SHARED_HOST, shared_host_check.KIND_LABELS, include_resolved, limit)


@router.post("/api/monitoring/cato-shared-hosts/run")
@scoped("refused")
async def run_cato_shared_host_check_api(request: Request):
    """Run the check now (every account: refused to a scoped caller)."""
    return await base.run_api(request, SHARED_HOST, run_shared_host_check)
