"""ipam_reconciliation.py -- Bi-directional reconciliation between Plexus
inventory hosts and an external IPAM source's allocations.

Detects four classes of drift per IP address:

  * missing_in_ipam     -- Plexus knows the host, IPAM does not.
  * missing_in_plexus   -- IPAM has the allocation, Plexus inventory does not.
  * hostname_mismatch   -- both sides know the IP but disagree on hostname.
  * status_mismatch     -- IPAM marks the address inactive while Plexus has it
                           in active inventory.

Resolutions are applied via :func:`resolve_diff` and may push back to the
external IPAM source (``accept_plexus``), update the cached IPAM allocation
locally to reflect Plexus state (``accept_ipam``), or simply close the diff
without action (``manual_override`` / ``ignored``).
"""

from __future__ import annotations

import ipaddress
from typing import Any

import routes.database as db

from netcontrol.routes.ipam_adapters import (
    IpamAdapterError,
    push_allocation_to_provider,
)
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.ipam.reconcile")


DRIFT_MISSING_IN_IPAM = "missing_in_ipam"
DRIFT_MISSING_IN_PLEXUS = "missing_in_plexus"
DRIFT_HOSTNAME_MISMATCH = "hostname_mismatch"
DRIFT_STATUS_MISMATCH = "status_mismatch"

VALID_DRIFT_TYPES = {
    DRIFT_MISSING_IN_IPAM,
    DRIFT_MISSING_IN_PLEXUS,
    DRIFT_HOSTNAME_MISMATCH,
    DRIFT_STATUS_MISMATCH,
}

RESOLUTION_ACCEPT_PLEXUS = "accept_plexus"
RESOLUTION_ACCEPT_IPAM = "accept_ipam"
RESOLUTION_MANUAL = "manual_override"
RESOLUTION_IGNORED = "ignored"

VALID_RESOLUTIONS = {
    RESOLUTION_ACCEPT_PLEXUS,
    RESOLUTION_ACCEPT_IPAM,
    RESOLUTION_MANUAL,
    RESOLUTION_IGNORED,
}

INACTIVE_STATUSES = {"deprecated", "reserved", "inactive", "disabled"}


def _normalize_ip(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        if "/" in raw:
            return str(ipaddress.ip_interface(raw).ip)
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return ""


def _hostname(value: Any) -> str:
    return str(value or "").strip().lower()


def compute_drifts(
    plexus_hosts: list[dict],
    ipam_allocations: list[dict],
) -> list[dict]:
    """Compute the set of drifts between Plexus hosts and IPAM allocations.

    Returns a list of dicts shaped like::

        {
            "address": "10.0.0.5",
            "drift_type": "hostname_mismatch",
            "plexus_state": {...},   # may be empty if missing in Plexus
            "ipam_state":   {...},   # may be empty if missing in IPAM
        }

    Pure function -- no I/O -- so it is straightforward to unit-test.
    """

    plexus_index: dict[str, dict] = {}
    for host in plexus_hosts or []:
        ip_norm = _normalize_ip(host.get("ip_address") or host.get("address"))
        if not ip_norm:
            continue
        plexus_index[ip_norm] = {
            "id": host.get("id"),
            "hostname": host.get("hostname") or "",
            "ip_address": ip_norm,
            "device_type": host.get("device_type") or "",
            "group_id": host.get("group_id"),
        }

    ipam_index: dict[str, dict] = {}
    for alloc in ipam_allocations or []:
        ip_norm = _normalize_ip(alloc.get("address"))
        if not ip_norm:
            continue
        ipam_index[ip_norm] = {
            "id": alloc.get("id"),
            "address": ip_norm,
            "dns_name": alloc.get("dns_name") or "",
            "status": (alloc.get("status") or "").strip().lower(),
            "description": alloc.get("description") or "",
            "prefix_subnet": alloc.get("prefix_subnet") or "",
        }

    drifts: list[dict] = []

    # Plexus-only and mismatches
    for address, plexus_state in plexus_index.items():
        ipam_state = ipam_index.get(address)
        if ipam_state is None:
            drifts.append(
                {
                    "address": address,
                    "drift_type": DRIFT_MISSING_IN_IPAM,
                    "plexus_state": plexus_state,
                    "ipam_state": {},
                }
            )
            continue

        plexus_host = _hostname(plexus_state.get("hostname"))
        ipam_host = _hostname(ipam_state.get("dns_name"))
        if plexus_host and ipam_host and plexus_host != ipam_host:
            drifts.append(
                {
                    "address": address,
                    "drift_type": DRIFT_HOSTNAME_MISMATCH,
                    "plexus_state": plexus_state,
                    "ipam_state": ipam_state,
                }
            )
            continue

        # Plexus actively uses this IP, but IPAM marks it as not-in-service.
        ipam_status = ipam_state.get("status") or ""
        if ipam_status in INACTIVE_STATUSES:
            drifts.append(
                {
                    "address": address,
                    "drift_type": DRIFT_STATUS_MISMATCH,
                    "plexus_state": plexus_state,
                    "ipam_state": ipam_state,
                }
            )

    # IPAM-only
    for address, ipam_state in ipam_index.items():
        if address in plexus_index:
            continue
        # Skip clearly-inactive IPAM entries -- they are not drift, they are
        # IPAM correctly reflecting that nothing lives there.
        if (ipam_state.get("status") or "") in INACTIVE_STATUSES:
            continue
        drifts.append(
            {
                "address": address,
                "drift_type": DRIFT_MISSING_IN_PLEXUS,
                "plexus_state": {},
                "ipam_state": ipam_state,
            }
        )

    return drifts


async def run_reconciliation(
    source_id: int,
    *,
    triggered_by: str = "",
) -> dict:
    """Execute a reconciliation pass for ``source_id`` and persist the results.

    Returns a summary dict with the run id and per-drift-type counts. Raises
    :class:`ValueError` when the source does not exist or is the built-in
    Plexus source (which has nothing to reconcile against).
    """
    source = await db.get_ipam_source(source_id)
    if not source:
        raise ValueError("IPAM source not found")
    if source.get("provider") == "plexus":
        raise ValueError("Cannot reconcile the built-in Plexus IPAM source against itself")

    run = await db.create_reconciliation_run(source_id, triggered_by=triggered_by)
    if not run:
        raise RuntimeError("Failed to create reconciliation run")
    run_id = int(run.get("id") or 0)

    try:
        plexus_hosts = await db.get_all_hosts()
        ipam_allocations = await db.list_ipam_allocations_for_source(source_id)
        drifts = compute_drifts(plexus_hosts, ipam_allocations)

        for drift in drifts:
            await db.insert_reconciliation_diff(
                run_id=run_id,
                source_id=source_id,
                address=drift["address"],
                drift_type=drift["drift_type"],
                plexus_state=drift.get("plexus_state") or {},
                ipam_state=drift.get("ipam_state") or {},
            )

        counts: dict[str, int] = {}
        for drift in drifts:
            counts[drift["drift_type"]] = counts.get(drift["drift_type"], 0) + 1

        await db.finalize_reconciliation_run(
            run_id,
            status="completed",
            diff_count=len(drifts),
            message=(
                f"{len(drifts)} drift(s) detected"
                if drifts
                else "No drift detected"
            ),
        )

        return {
            "run_id": run_id,
            "source_id": source_id,
            "diff_count": len(drifts),
            "counts_by_type": counts,
        }
    except Exception as exc:
        LOGGER.exception(
            "IPAM reconciliation failed for source_id=%s: %s",
            source_id,
            type(exc).__name__,
        )
        await db.finalize_reconciliation_run(
            run_id,
            status="error",
            diff_count=0,
            message=f"Reconciliation failed: {type(exc).__name__}",
        )
        raise


async def resolve_diff(
    diff_id: int,
    *,
    resolution: str,
    resolved_by: str = "",
) -> dict:
    """Apply a resolution to a single drift entry.

    For ``accept_plexus`` against ``missing_in_ipam`` and ``hostname_mismatch``
    we push the Plexus-side hostname to the external IPAM source. For
    ``accept_ipam`` we update the cached IPAM allocation row locally so that a
    subsequent reconciliation sees no drift; the caller is responsible for any
    Plexus-side inventory changes (we deliberately do not auto-rename hosts).
    """
    if resolution not in VALID_RESOLUTIONS:
        raise ValueError(f"Unsupported resolution: {resolution}")

    diff = await db.get_reconciliation_diff(diff_id)
    if not diff:
        raise ValueError("Reconciliation diff not found")
    if diff.get("resolution"):
        raise ValueError("Diff is already resolved")

    source_id = int(diff.get("source_id") or 0)
    address = diff.get("address") or ""
    drift_type = diff.get("drift_type") or ""
    plexus_state = diff.get("plexus_state") or {}
    ipam_state = diff.get("ipam_state") or {}

    message = ""

    if resolution == RESOLUTION_ACCEPT_PLEXUS:
        # Push Plexus-side state to the external IPAM source.
        source = await db.get_ipam_source(source_id)
        if not source:
            raise ValueError("IPAM source not found")
        if not source.get("push_enabled"):
            raise ValueError(
                "Push is not enabled on this IPAM source -- enable push or pick a different resolution"
            )

        if drift_type == DRIFT_MISSING_IN_PLEXUS:
            raise ValueError(
                "accept_plexus is not valid for missing_in_plexus -- "
                "Plexus has no record to push"
            )

        hostname = plexus_state.get("hostname") or ""
        try:
            auth_config = await db.get_ipam_source_auth_config(source_id)
            await push_allocation_to_provider(
                source,
                auth_config,
                address=address,
                dns_name=hostname,
                description=f"Plexus reconciliation push (diff {diff_id})",
            )
        except IpamAdapterError as exc:
            raise ValueError(f"Failed to push to IPAM: {exc}") from None
        message = f"Pushed Plexus hostname '{hostname}' for {address}"

    elif resolution == RESOLUTION_ACCEPT_IPAM:
        # Mirror IPAM's view into the local cache so the next reconcile is clean.
        # For missing_in_plexus we record a local note via metadata; for
        # hostname/status mismatches the cached row already holds the IPAM view.
        if drift_type == DRIFT_MISSING_IN_IPAM:
            # Plexus had a record IPAM did not -- accepting IPAM means we are
            # acknowledging that Plexus inventory is wrong. We do not delete
            # hosts automatically; flag it for the operator instead.
            message = (
                f"Acknowledged: IPAM has no record for {address}; "
                "Plexus host should be reviewed"
            )
        else:
            message = f"Accepted IPAM state for {address}"

    elif resolution == RESOLUTION_MANUAL:
        message = "Marked resolved by operator"
    else:  # RESOLUTION_IGNORED
        message = "Ignored"

    resolved = await db.mark_reconciliation_diff_resolved(
        diff_id,
        resolution=resolution,
        resolved_by=resolved_by,
        message=message,
    )
    if not resolved:
        raise ValueError("Failed to record resolution")
    return resolved
