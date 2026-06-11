"""
mac_tracking.py -- MacTrack-style MAC/ARP/port tracking

Provides:
  - SNMP-based MAC address table collection (dot1dTpFdbTable, dot1qTpFdbTable)
  - SNMP-based ARP table collection (ipNetToMediaTable)
  - MAC/ARP search and history API endpoints
  - Background collection loop integration
"""
from __future__ import annotations

import asyncio
import json
import socket
import time

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

import netcontrol.routes.state as state
from netcontrol.routes import background_jobs
from netcontrol.routes.shared import _audit, _corr_id, _get_session
from netcontrol.routes.snmp import _build_snmp_auth, _snmp_str, _snmp_walk
from netcontrol.telemetry import configure_logging

router = APIRouter()
LOGGER = configure_logging("plexus.mac_tracking")


# ═════════════════════════════════════════════════════════════════════════════
# SNMP OIDs for MAC/ARP Collection
# ═════════════════════════════════════════════════════════════════════════════

# Bridge forwarding table (standard)
DOT1D_TP_FDB_ADDRESS = "1.3.6.1.2.1.17.4.3.1.1"   # dot1dTpFdbAddress
DOT1D_TP_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"      # dot1dTpFdbPort
DOT1D_TP_FDB_STATUS = "1.3.6.1.2.1.17.4.3.1.3"    # dot1dTpFdbStatus

# VLAN-aware forwarding table (Q-BRIDGE-MIB)
DOT1Q_TP_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"  # dot1qTpFdbPort

# Bridge port to ifIndex mapping
DOT1D_BASE_PORT_IF_INDEX = "1.3.6.1.2.1.17.1.4.1.2"  # dot1dBasePortIfIndex

# Per-port VLAN membership (used to tag MACs without per-VLAN context walks)
VM_VLAN_OID = "1.3.6.1.4.1.9.9.68.1.2.2.1.2"          # Cisco vmVlan (access port VLAN), indexed by ifIndex
DOT1Q_PVID_OID = "1.3.6.1.2.1.17.7.1.4.5.1.1"         # dot1qPvid, indexed by dot1dBasePort

# Switch-wide VLAN inventory (used to seed per-VLAN context walks even when no
# access ports report the VLAN — e.g. trunk-only VLANs or VLANs whose access
# ports are admin-down). VTP is Cisco-specific; dot1qVlanStaticName is the
# standard Q-BRIDGE counterpart.
VTP_VLAN_NAME_OID = "1.3.6.1.4.1.9.9.46.1.3.1.1.4"        # vtpVlanName (per management domain + vlan id)
DOT1Q_VLAN_STATIC_NAME_OID = "1.3.6.1.2.1.17.7.1.4.3.1.1"  # dot1qVlanStaticName

# ARP table
IP_NET_TO_MEDIA_PHYS = "1.3.6.1.2.1.4.22.1.2"     # ipNetToMediaPhysAddress
IP_NET_TO_MEDIA_NET = "1.3.6.1.2.1.4.22.1.3"       # ipNetToMediaNetAddress
IP_NET_TO_MEDIA_TYPE = "1.3.6.1.2.1.4.22.1.4"      # ipNetToMediaType

# ifName for port resolution
IF_NAME_OID = "1.3.6.1.2.1.31.1.1.1.1"

# Status type mapping
FDB_STATUS_MAP = {
    "1": "other", "2": "invalid", "3": "learned",
    "4": "self", "5": "mgmt",
}

ARP_TYPE_MAP = {
    "1": "other", "2": "invalid", "3": "dynamic", "4": "static",
}

# A port reporting more distinct MACs than this in one collection is treated as
# an uplink/trunk rather than an access port. MACs seen there are recorded but
# excluded from move detection — every switch upstream of a host's real access
# port also sees that MAC on its uplink, so counting those as "moves" floods
# the move log with noise. 20 comfortably clears a busy access port (phones +
# PCs + a few VMs) while catching aggregation/uplink ports.
_UPLINK_MAC_THRESHOLD = 20


def _format_mac(raw_value) -> str:
    """Convert SNMP binary MAC address to colon-separated hex string."""
    try:
        raw_bytes = bytes(raw_value)
        if len(raw_bytes) == 6:
            return ":".join(f"{b:02x}" for b in raw_bytes)
        # Some implementations return hex string directly
        s = str(raw_value).strip()
        if len(s) == 12 and all(c in "0123456789abcdefABCDEF" for c in s):
            return ":".join(s[i:i+2].lower() for i in range(0, 12, 2))
        return s
    except Exception:
        return str(raw_value)


def _extract_mac_from_oid_suffix(suffix: str) -> str:
    """Extract MAC address from OID suffix (6 decimal octets)."""
    parts = suffix.split(".")
    if len(parts) >= 6:
        mac_parts = parts[-6:]
        try:
            return ":".join(f"{int(p):02x}" for p in mac_parts)
        except (ValueError, TypeError) as exc:
            LOGGER.debug("mac_tracking: could not parse MAC from OID suffix %r: %s", suffix, exc)
    return ""


# ═════════════════════════════════════════════════════════════════════════════
# SNMP Collection Functions
# ═════════════════════════════════════════════════════════════════════════════


async def collect_mac_arp_tables(host_id: int, ip_address: str,
                                  snmp_config: dict,
                                  timeout_seconds: float = 5.0,
                                  device_type: str = "",
                                  host: dict | None = None) -> dict:
    """Collect MAC and ARP tables from a device.

    MACs are pulled via SSH + ``show mac address-table`` parsed by
    ntc-templates when the host has a usable SSH credential and a driver
    that implements the capability. That path returns every MAC on every
    VLAN in one round-trip and sidesteps the Cisco "default-context FDB
    only shows VLAN 1" problem entirely. If the CLI path is unavailable
    (no driver, no SSH creds, SSH failure) the function falls back to
    SNMP collection of dot1dTpFdb / dot1qTpFdb plus the per-VLAN SNMPv3
    context dance on Cisco.

    ARP is always collected via SNMP (ipNetToMediaTable) — ARP isn't
    VLAN-scoped so the SNMP path works reliably for it.

    Pass the ``host`` dict to enable CLI MAC collection. When omitted the
    function is SNMP-only (preserves the legacy call signature for any
    caller that hasn't been updated yet).

    Returns {"macs_found", "arps_found", "errors", "diag"}.
    """
    # `diag` is surfaced to the API caller (see /api/mac-tracking/collect) so
    # operators can tell "per-VLAN block never ran" apart from "per-VLAN
    # block ran but every walk failed" without needing shell access to the
    # app server's logs.
    result = {
        "macs_found": 0, "arps_found": 0, "errors": [],
        "diag": {
            "device_type": device_type,
            "snmp_version": str(snmp_config.get("version", "")),
            "ports": 0,
            "port_vlans": 0,
            "vlans_discovered": 0,
            "vlan_ctx_attempted": 0,
            "vlan_ctx_succeeded": 0,
            "vlan_ctx_skipped": 0,
            "per_vlan_block_ran": False,
            "cli_attempted": False,
            "cli_succeeded": False,
            "cli_mac_count": 0,
        },
    }

    # ── Preferred path: collect MACs via CLI (SSH + ntc-templates) ──
    # SNMP MAC collection is a quagmire on Cisco (per-VLAN SNMPv3 context
    # required, view permissions, VTP enumeration) — we keep the SNMP
    # path as a fallback but try CLI first when we have what we need.
    cli_macs: list[dict] | None = None
    if host is not None:
        try:
            from netcontrol.drivers import DriverCapabilityError, get_driver
            from netcontrol.routes.shared import _collect_mac_table_via_cli

            # The driver registry only knows how to scrape MACs from L2
            # switch CLIs; bail out early for firewalls / routers / etc.
            # so we don't waste an SSH login on a definite no-op.
            try:
                get_driver(device_type).mac_table_show_command()
                driver_supports_cli = True
            except DriverCapabilityError:
                driver_supports_cli = False

            if driver_supports_cli:
                # Use the designated Plexus service credential for this
                # unattended SSH login (the same account monitoring polls
                # with), falling back to the legacy default credential for
                # deployments that haven't set one. The old code grabbed
                # whichever user credential happened to sort first, which
                # logged into devices as an arbitrary operator and pulled an
                # owned user credential into a background path — exactly what
                # the credential-ownership model is meant to prevent.
                cred_id = (
                    state.AUTH_CONFIG.get("service_credential_id")
                    or state.AUTH_CONFIG.get("default_credential_id")
                )
                service_cred = await db.get_credential_raw(cred_id) if cred_id else None
                if service_cred is None:
                    result["errors"].append(
                        "CLI MAC collection skipped: no service or default "
                        "credential configured (set one in Settings); using SNMP."
                    )
                else:
                    result["diag"]["cli_attempted"] = True
                    try:
                        cli_macs = await _collect_mac_table_via_cli(
                            host, service_cred
                        )
                        result["diag"]["cli_succeeded"] = True
                        result["diag"]["cli_mac_count"] = len(cli_macs)
                    except Exception as exc:
                        # SSH/auth/timeout errors land here. Don't abort —
                        # the SNMP fallback below may still produce useful
                        # data. The operator sees the failure in the
                        # returned errors array.
                        result["errors"].append(
                            f"CLI MAC collection failed ({type(exc).__name__}): "
                            f"{exc}; falling back to SNMP"
                        )
        except Exception as exc:
            # Defensive: anything that goes wrong in the CLI setup path
            # (e.g. import error, db lookup) shouldn't break SNMP.
            result["errors"].append(f"CLI MAC setup failed: {exc}")

    def _walk(oid: str, max_rows: int = 2000):
        return _snmp_walk(ip_address, timeout_seconds, snmp_config, oid, max_rows=max_rows)

    def _walk_with_errors(oid: str, max_rows: int = 2000):
        return _snmp_walk(
            ip_address, timeout_seconds, snmp_config, oid,
            max_rows=max_rows, return_errors=True,
        )

    # ── Single global pass: everything lives in the default context ──
    # The "critical" OIDs (FDB tables + ARP) ask for error-aware results so
    # we can tell silent-but-responsive devices from outright SNMP failures.
    # The supporting OIDs (vlan map, ifName, etc.) stay in the plain mode —
    # they're allowed to be empty without it counting as a failure.
    try:
        (arp_phys_pair,
         arp_net, arp_type_rows,
         if_names, vm_vlan, dot1q_pvid,
         fdb_addr_pair, fdb_port, fdb_status, q_fdb_port_pair, bridge_port_map,
         vtp_vlan_names, dot1q_static_vlan_names,
        ) = await asyncio.gather(
            _walk_with_errors(IP_NET_TO_MEDIA_PHYS),
            _walk(IP_NET_TO_MEDIA_NET),
            _walk(IP_NET_TO_MEDIA_TYPE),
            _walk(IF_NAME_OID),
            _walk(VM_VLAN_OID),
            _walk(DOT1Q_PVID_OID),
            _walk_with_errors(DOT1D_TP_FDB_ADDRESS),
            _walk(DOT1D_TP_FDB_PORT),
            _walk(DOT1D_TP_FDB_STATUS),
            _walk_with_errors(DOT1Q_TP_FDB_PORT),
            _walk(DOT1D_BASE_PORT_IF_INDEX),
            _walk(VTP_VLAN_NAME_OID),
            _walk(DOT1Q_VLAN_STATIC_NAME_OID),
        )
    except Exception as exc:
        result["errors"].append(f"SNMP walk failed: {str(exc)}")
        return result

    arp_phys, arp_phys_err = arp_phys_pair
    fdb_addr, fdb_addr_err = fdb_addr_pair
    q_fdb_port, q_fdb_port_err = q_fdb_port_pair

    # Record critical-walk errors verbatim. If *both* FDB walks failed with
    # the same error (almost always: timeout / auth fail / closed port), say
    # it once instead of three times.
    fdb_errors = {e for e in (fdb_addr_err, q_fdb_port_err) if e}
    if fdb_errors:
        if len(fdb_errors) == 1:
            result["errors"].append(f"FDB walk failed: {next(iter(fdb_errors))}")
        else:
            for tag, err in (("dot1dTpFdb", fdb_addr_err),
                              ("dot1qTpFdb", q_fdb_port_err)):
                if err:
                    result["errors"].append(f"{tag} walk failed: {err}")
    if arp_phys_err:
        result["errors"].append(f"ARP walk failed: {arp_phys_err}")

    # NB: the "device responded but returned no FDB entries" advisory used to
    # live here, but on Cisco the default-context walk is *expected* to be
    # near-empty — the real FDB lives in per-VLAN contexts and is collected
    # below. The advisory now runs after the per-VLAN merge so it only fires
    # when the merged result is genuinely empty.

    if_index_to_name: dict[str, str] = {}
    for oid, val in if_names.items():
        idx = oid.rsplit(".", 1)[-1] if "." in oid else ""
        if idx:
            if_index_to_name[idx] = _snmp_str(val)

    bp_to_if_index: dict[str, str] = {}
    for oid, val in bridge_port_map.items():
        bp = oid.rsplit(".", 1)[-1] if "." in oid else ""
        if bp:
            bp_to_if_index[bp] = str(val).strip()

    # ── Build if_index → vlan map ──
    # vmVlan (Cisco) is indexed directly by ifIndex; dot1qPvid is indexed by
    # dot1dBasePort and needs translating. vmVlan wins when both are present
    # because trunk ports report a vacuous PVID that would mislabel learned
    # MACs.
    if_index_to_vlan: dict[str, int] = {}
    for oid, val in dot1q_pvid.items():
        bp = oid.rsplit(".", 1)[-1] if "." in oid else ""
        if_idx = bp_to_if_index.get(bp)
        if not if_idx:
            continue
        try:
            vid = int(str(val).strip())
        except (ValueError, TypeError):
            continue
        if 1 <= vid <= 4094:
            if_index_to_vlan[if_idx] = vid
    for oid, val in vm_vlan.items():
        if_idx = oid.rsplit(".", 1)[-1] if "." in oid else ""
        if not if_idx:
            continue
        try:
            vid = int(str(val).strip())
        except (ValueError, TypeError):
            continue
        if 1 <= vid <= 4094:
            if_index_to_vlan[if_idx] = vid

    def _resolve_port(bridge_port: str) -> tuple[str, int, int]:
        if_idx = bp_to_if_index.get(bridge_port, bridge_port)
        port_name = if_index_to_name.get(if_idx, f"port-{bridge_port}")
        try:
            port_index = int(if_idx)
        except (ValueError, TypeError):
            port_index = 0
        port_vlan = if_index_to_vlan.get(if_idx, 0)
        return port_name, port_index, port_vlan

    # ── Cisco SNMPv3 per-VLAN FDB walks ────────────────────────────────
    # The default-context FDB only returns VLAN 1 on IOS/IOS-XE, so without
    # this re-walk we'd see uplink-only MACs (exactly the symptom that
    # prompted this code path). Per-VLAN context is a Cisco-specific trick;
    # other vendors put VLAN-in-OID into the default-context dot1qTpFdbTable
    # already, so we skip them.
    version = str(snmp_config.get("version", "")).strip().lower()
    is_cisco = device_type.lower().startswith("cisco")

    # ── Enumerate every VLAN configured on the switch ───────────────────
    # Access-port PVIDs only cover VLANs that have access ports assigned to
    # them. A trunk-only VLAN (or one whose access ports are admin-down)
    # would never appear there, so its FDB never got walked and every MAC
    # learnt on a trunk for that VLAN was missed. Adding the VTP table
    # (Cisco) and dot1qVlanStaticTable (standard) catches them. Both walks
    # are indexed by VLAN id in their last OID component.
    def _vids_from_walk(walk: dict[str, str]) -> set[int]:
        out: set[int] = set()
        for oid in walk.keys():
            suffix = oid.rsplit(".", 1)[-1] if "." in oid else ""
            try:
                vid = int(suffix)
            except (ValueError, TypeError):
                continue
            if 1 <= vid <= 4094:
                out.add(vid)
        return out

    # 1002-1005 are the legacy FDDI/Token Ring default VLANs Cisco still
    # ships in the VTP table; they exist on every IOS switch but never
    # carry traffic, so we skip them to avoid pointless context walks.
    RESERVED_VLAN_IDS = {1002, 1003, 1004, 1005}
    discovered_vlans = (
        {v for v in if_index_to_vlan.values() if 1 <= v <= 4094}
        | _vids_from_walk(vtp_vlan_names)
        | _vids_from_walk(dot1q_static_vlan_names)
    ) - RESERVED_VLAN_IDS
    vlans_in_use = sorted(discovered_vlans)
    per_vlan_errors: list[str] = []
    per_vlan_attempts = 0
    per_vlan_successes = 0
    per_vlan_skipped = 0
    # dot1dTpFdb rows carry no VLAN in their OID, so a per-VLAN context walk is
    # the only thing that knows which VLAN they belong to. We keep each
    # context's rows separately (tagged with the context VLAN) rather than
    # merging them into one shared dict — merging loses the VLAN and makes
    # same-MAC-in-many-VLANs entries (HSRP/VRRP virtual MACs) collapse onto
    # whichever parallel context happened to finish last.
    per_vlan_dot1d: list[tuple[int, dict, dict, dict]] = []
    result["diag"]["vlans_discovered"] = len(vlans_in_use)
    # When the CLI already gave us the full MAC table, skip the per-VLAN
    # SNMP block entirely — it's the slow, fragile part and CLI is
    # authoritative. The default-context SNMP FDB processing further down
    # still runs, but it'll be a no-op for any (mac, vlan) we already
    # upserted from CLI because seen_mac_vlan dedups it.
    if cli_macs is not None and cli_macs:
        pass  # CLI succeeded; skip per-VLAN block
    elif is_cisco and version in ("v3", "3") and vlans_in_use:
        result["diag"]["per_vlan_block_ran"] = True
        # Walk per-VLAN contexts with bounded concurrency. The old loop ran
        # strictly sequentially with 4 walks per VLAN (q-bridge + three
        # dot1d) — at ~3s/walk that's >20 minutes on a switch carrying a
        # full VTP table. Two changes here:
        #   1. Fast path: dot1qTpFdbPort exposes the same FDB rows as the
        #      three dot1d* tables (with the VLAN in the OID suffix, even),
        #      so when it returns rows we skip the dot1d walks entirely.
        #      Empty q-bridge → fall back to dot1d for the rare device that
        #      only populates the standard bridge MIB per-context.
        #   2. Bounded parallelism: cap concurrent VLAN contexts at 4. The
        #      original "single Catalyst CPU melts under unbounded parallel
        #      SNMPv3" comment still applies, but 4 is well under that
        #      threshold on every device class we've tested.
        # A wall-clock deadline guards against pathological cases (huge VTP
        # domain on a slow agent) so the collector never hangs forever.
        per_vlan_sem = asyncio.Semaphore(4)
        deadline = time.monotonic() + 60.0

        async def _walk_one_vlan(vid: int) -> dict:
            if time.monotonic() > deadline:
                return {"vid": vid, "skipped": True}
            async with per_vlan_sem:
                if time.monotonic() > deadline:
                    return {"vid": vid, "skipped": True}
                ctx_cfg = dict(snmp_config)
                ctx_cfg["snmp_context"] = f"vlan-{vid}"
                try:
                    q_rows, q_err = await _snmp_walk(
                        ip_address, timeout_seconds, ctx_cfg, DOT1Q_TP_FDB_PORT,
                        max_rows=2000, return_errors=True,
                    )
                except Exception as exc:
                    return {"vid": vid, "error": f"vlan-{vid}: {type(exc).__name__}: {exc}"}

                # Fast path: q-bridge had data, skip dot1d entirely.
                if q_rows:
                    return {"vid": vid, "q_rows": q_rows, "q_err": q_err}

                # Fallback: walk the three dot1d tables in parallel — same
                # context, no reason to serialise them against each other.
                try:
                    d_addr_pair, d_port_rows, d_status_rows = await asyncio.gather(
                        _snmp_walk(ip_address, timeout_seconds, ctx_cfg,
                                   DOT1D_TP_FDB_ADDRESS, max_rows=2000,
                                   return_errors=True),
                        _snmp_walk(ip_address, timeout_seconds, ctx_cfg,
                                   DOT1D_TP_FDB_PORT, max_rows=2000),
                        _snmp_walk(ip_address, timeout_seconds, ctx_cfg,
                                   DOT1D_TP_FDB_STATUS, max_rows=2000),
                    )
                except Exception as exc:
                    return {"vid": vid, "error": f"vlan-{vid}: {type(exc).__name__}: {exc}"}
                d_addr_rows, d_addr_err = d_addr_pair
                return {
                    "vid": vid,
                    "q_rows": q_rows, "q_err": q_err,
                    "d_addr_rows": d_addr_rows, "d_addr_err": d_addr_err,
                    "d_port_rows": d_port_rows,
                    "d_status_rows": d_status_rows,
                }

        per_vlan_attempts = len(vlans_in_use)
        vlan_results = await asyncio.gather(
            *(_walk_one_vlan(vid) for vid in vlans_in_use),
            return_exceptions=True,
        )

        for r in vlan_results:
            if isinstance(r, Exception):
                per_vlan_errors.append(f"unexpected: {type(r).__name__}: {r}")
                continue
            if r.get("skipped"):
                per_vlan_skipped += 1
                continue
            if "error" in r:
                per_vlan_errors.append(r["error"])
                continue
            vid = r["vid"]
            q_rows = r.get("q_rows", {})
            d_addr_rows = r.get("d_addr_rows", {})
            d_port_rows = r.get("d_port_rows", {})
            d_status_rows = r.get("d_status_rows", {})
            # An auth/timeout error on one VLAN context is recorded but
            # doesn't poison the run — the operator's v3 user may simply
            # lack a view on that VLAN.
            ctx_err = r.get("q_err") or r.get("d_addr_err")
            if ctx_err and not q_rows and not d_addr_rows:
                per_vlan_errors.append(f"vlan-{vid}: {ctx_err}")
                continue
            if q_rows or d_addr_rows:
                per_vlan_successes += 1
            # The dot1qTpFdbPort OID encodes the VLAN in its suffix, so rows
            # from different VLAN contexts coexist in one dict without
            # colliding — safe to merge.
            q_fdb_port.update(q_rows)
            # dot1dTpFdb* rows are bridge-scoped (no VLAN in the OID). Keep each
            # context's rows tagged with this VLAN instead of merging, so the
            # emission pass below assigns the right VLAN even when the same MAC
            # appears in several contexts.
            if d_addr_rows:
                per_vlan_dot1d.append((vid, d_addr_rows, d_port_rows, d_status_rows))

        if per_vlan_skipped:
            result["errors"].append(
                f"Per-VLAN walks hit 60s budget — skipped {per_vlan_skipped} "
                f"of {per_vlan_attempts} VLAN contexts. Increase budget or "
                f"reduce VTP scope if MACs on those VLANs are missing."
            )
        if per_vlan_attempts and per_vlan_successes == 0 and not per_vlan_skipped:
            # Every VLAN context failed — the device is reachable (we got the
            # vmVlan map) but the operator can't see any FDB view. That's a
            # configuration problem on the device, surface it loudly.
            result["errors"].append(
                f"All {per_vlan_attempts} per-VLAN FDB walks failed "
                f"(SNMPv3 user likely lacks 'snmp-server group ... read' on the per-VLAN views)."
            )
        elif per_vlan_errors:
            # Some succeeded, some didn't — informational rather than fatal.
            # Cap the list so we don't dump 50 lines for a chatty device.
            preview = "; ".join(per_vlan_errors[:5])
            suffix = f" (+{len(per_vlan_errors) - 5} more)" if len(per_vlan_errors) > 5 else ""
            result["errors"].append(
                f"Per-VLAN FDB walks partially failed: {preview}{suffix}"
            )

    # ── Assemble the authoritative (mac, vlan) → location map ────────────
    # One sighting per (mac, vlan), chosen by source priority so the most
    # trustworthy VLAN/port wins and nothing is written twice:
    #   1. CLI scrape          - full per-VLAN table in one round-trip
    #   2. Q-BRIDGE FDB        - VLAN encoded in the OID (default + per-VLAN ctx)
    #   3. per-VLAN dot1d FDB  - VLAN known from the SNMPv3 context
    #   4. default-ctx dot1d   - VLAN guessed from the learning port's PVID
    sightings: dict[tuple[str, int], dict] = {}

    def _add_sighting(mac: str, vlan: int, port_name: str,
                      port_index: int, entry_type: str) -> None:
        if not mac:
            return
        sightings.setdefault((mac, vlan), {
            "mac": mac, "vlan": vlan, "port_name": port_name,
            "port_index": port_index, "entry_type": entry_type,
        })

    # 1. CLI rows (authoritative when present).
    if cli_macs:
        for row in cli_macs:
            _add_sighting(row["mac"], row["vlan"], row["port"], 0, row["type"])

    # Only parse the SNMP FDB when the CLI scrape didn't already give us the
    # full table. Running both would write each MAC twice under mismatched
    # VLAN/port spellings (CLI "Gi1/0/1" vs ifName "GigabitEthernet1/0/1") and
    # make the change detector see a phantom move on every poll.
    if not cli_macs:
        # 2. Q-BRIDGE FDB (default context + any per-VLAN contexts merged in).
        for oid, port_val in q_fdb_port.items():
            suffix = oid[len(DOT1Q_TP_FDB_PORT):].lstrip(".")
            parts = suffix.split(".")
            port_name, port_index, port_vlan = _resolve_port(str(port_val))
            if len(parts) >= 7:
                try:
                    vlan = int(parts[0])
                except (ValueError, TypeError):
                    vlan = port_vlan
                mac = _extract_mac_from_oid_suffix(".".join(parts[1:7]))
            else:
                vlan = port_vlan
                mac = _extract_mac_from_oid_suffix(suffix)
            _add_sighting(mac, vlan, port_name, port_index, "dynamic")

        # 3. per-VLAN-context dot1d FDB — VLAN is the context id, not the OID.
        for vid, d_addr_rows, d_port_rows, d_status_rows in per_vlan_dot1d:
            for oid, mac_val in d_addr_rows.items():
                suffix = oid[len(DOT1D_TP_FDB_ADDRESS):].lstrip(".")
                mac = _format_mac(mac_val)
                if not mac or len(mac) < 12:
                    mac = _extract_mac_from_oid_suffix(suffix)
                if not mac:
                    continue
                bridge_port = str(d_port_rows.get(DOT1D_TP_FDB_PORT + "." + suffix, "0"))
                status = FDB_STATUS_MAP.get(
                    str(d_status_rows.get(DOT1D_TP_FDB_STATUS + "." + suffix, "")), "dynamic")
                port_name, port_index, _ = _resolve_port(bridge_port)
                _add_sighting(mac, vid, port_name, port_index, status)

        # 4. default-context dot1d FDB — VLAN falls back to the port's PVID.
        for oid, mac_val in fdb_addr.items():
            suffix = oid[len(DOT1D_TP_FDB_ADDRESS):].lstrip(".")
            mac = _format_mac(mac_val)
            if not mac or len(mac) < 12:
                mac = _extract_mac_from_oid_suffix(suffix)
            if not mac:
                continue
            bridge_port = str(fdb_port.get(DOT1D_TP_FDB_PORT + "." + suffix, "0"))
            status = FDB_STATUS_MAP.get(
                str(fdb_status.get(DOT1D_TP_FDB_STATUS + "." + suffix, "")), "dynamic")
            port_name, port_index, port_vlan = _resolve_port(bridge_port)
            _add_sighting(mac, port_vlan, port_name, port_index, status)

    # Final empty-FDB advisory — only when nothing at all turned up and no
    # protocol error explains it: the genuine "this device doesn't bridge" case.
    if not sightings and not fdb_errors and not per_vlan_errors:
        result["errors"].append(
            "Device responded but returned no FDB entries "
            "(likely a router / L3-only device, or FDB hidden behind a non-default SNMPv3 context)."
        )

    # ── Identify uplink/trunk ports ──────────────────────────────────────
    # A port carrying many distinct MACs is an uplink/trunk, not an access
    # location. We still record those MACs (the FDB is real) but tell
    # record_mac_history to skip move detection for them — otherwise every
    # switch between a host and its access edge would log a "move" each poll.
    port_mac_counts: dict[str, int] = {}
    for s in sightings.values():
        port_mac_counts[s["port_name"]] = port_mac_counts.get(s["port_name"], 0) + 1

    # ── Write the deduplicated sightings ─────────────────────────────────
    # One batched transaction per host instead of two awaited round-trips per
    # MAC (upsert + history each opened and closed a connection - tens of
    # thousands of connection cycles per fleet collection).
    sighting_batch = [
        {
            "mac": s["mac"], "vlan": s["vlan"],
            "port_name": s["port_name"], "port_index": s["port_index"],
            "entry_type": s["entry_type"],
            "is_uplink": port_mac_counts.get(s["port_name"], 0) > _UPLINK_MAC_THRESHOLD,
        }
        for s in sightings.values()
    ]
    try:
        counts = await db.record_mac_sightings_batch(host_id, sighting_batch)
        result["macs_found"] += counts["macs"]
    except Exception as exc:
        LOGGER.warning("mac_tracking: host %s MAC batch write failed (%d sightings): %s",
                       host_id, len(sighting_batch), exc)
        result["errors"].append(f"MAC table write failed: {exc}")

    # ── ARP table (global, ipNetToMediaTable) ──
    arp_batch: list[dict] = []
    for oid, mac_val in arp_phys.items():
        suffix = oid[len(IP_NET_TO_MEDIA_PHYS):].lstrip(".")
        mac = _format_mac(mac_val)
        if not mac:
            continue

        # Extract IP: suffix format is <if_index>.<ip_a>.<ip_b>.<ip_c>.<ip_d>
        parts = suffix.split(".")
        if len(parts) >= 5:
            ip_addr = ".".join(parts[1:5])
            if_idx = parts[0]
        else:
            ip_addr = ""
            if_idx = ""

        iface_name = if_index_to_name.get(if_idx, "")
        type_oid = IP_NET_TO_MEDIA_TYPE + "." + suffix
        arp_type = ARP_TYPE_MAP.get(str(arp_type_rows.get(type_oid, "")), "dynamic")

        arp_batch.append({
            "ip_address": ip_addr, "mac_address": mac,
            "interface_name": iface_name,
        })

    # One batched transaction: ARP upserts plus the cross-host IP enrichment
    # of mac_address_table (the access switch holds the FDB row; this L3
    # device holds the ARP binding), instead of two round-trips per entry.
    if arp_batch:
        try:
            result["arps_found"] += await db.upsert_arp_entries_batch(host_id, arp_batch)
        except Exception as exc:
            LOGGER.warning("mac_tracking: host %s ARP batch write failed (%d entries): %s",
                           host_id, len(arp_batch), exc)
            result["errors"].append(f"ARP table write failed: {exc}")

    result["diag"]["ports"] = len(if_index_to_name)
    result["diag"]["port_vlans"] = len(if_index_to_vlan)
    result["diag"]["vlan_ctx_attempted"] = per_vlan_attempts
    result["diag"]["vlan_ctx_succeeded"] = per_vlan_successes
    result["diag"]["vlan_ctx_skipped"] = per_vlan_skipped
    LOGGER.info(
        "mac_tracking: host %s (%s) ports=%d port_vlans=%d "
        "vlans_discovered=%d vlan_ctx=%d/%d (skipped=%d) "
        "cli=%s(%d) - %d MACs, %d ARPs collected",
        host_id, ip_address, len(if_index_to_name), len(if_index_to_vlan),
        len(vlans_in_use),
        per_vlan_successes, per_vlan_attempts, per_vlan_skipped,
        "ok" if result["diag"]["cli_succeeded"]
        else ("fail" if result["diag"]["cli_attempted"] else "skip"),
        result["diag"]["cli_mac_count"],
        result["macs_found"], result["arps_found"],
    )
    return result


# ═════════════════════════════════════════════════════════════════════════════
# Interface inventory + VLAN definitions (audit collector)
# ═════════════════════════════════════════════════════════════════════════════
#
# Walks the standard IF-MIB + VTP MIB to feed the audit subsystem's
# port-hygiene and VLAN-consistency rules. Folded into the mac_tracking
# module (and called from the same topology-discovery hot path) so we
# don't spin up another background loop just for these tables. The OIDs
# are read-only and the writes go through the normal sqlite upsert path,
# so calling it every discovery cycle is cheap and idempotent.

# IF-MIB OIDs reused for the inventory snapshot
IF_DESCR_OID = "1.3.6.1.2.1.2.2.1.2"               # ifDescr (fallback name)
IF_ALIAS_OID = "1.3.6.1.2.1.31.1.1.1.18"           # ifAlias (description)
IF_ADMIN_STATUS_OID = "1.3.6.1.2.1.2.2.1.7"         # 1=up 2=down 3=testing
IF_OPER_STATUS_OID = "1.3.6.1.2.1.2.2.1.8"          # 1=up 2=down ...
IF_HIGH_SPEED_OID = "1.3.6.1.2.1.31.1.1.1.15"       # Mbps
IF_SPEED_OID = "1.3.6.1.2.1.2.2.1.5"                # bps fallback
IF_LAST_CHANGE_OID = "1.3.6.1.2.1.2.2.1.9"          # sysUptime ticks at last admin/oper transition
DOT3_STATS_DUPLEX_OID = "1.3.6.1.2.1.10.7.2.1.19"   # 1=unknown 2=half 3=full

# Cisco VTP VLAN states (vtpVlanName itself is declared above; the FDB
# collector seeds per-VLAN context walks from it, so it lives at module top).
VTP_VLAN_STATE_OID = "1.3.6.1.4.1.9.9.46.1.3.1.1.2"  # vtpVlanState (1=operational ...)

# Cisco VTP trunk allowed-VLAN bitmaps (1k/2k/3k/4k slices, 128 bytes each)
VTP_TRUNK_VLANS_OID = "1.3.6.1.4.1.9.9.46.1.6.1.1.4"      # vlans 0..1023
VTP_TRUNK_VLANS_2K_OID = "1.3.6.1.4.1.9.9.46.1.6.1.1.17"   # 1024..2047
VTP_TRUNK_VLANS_3K_OID = "1.3.6.1.4.1.9.9.46.1.6.1.1.18"   # 2048..3071
VTP_TRUNK_VLANS_4K_OID = "1.3.6.1.4.1.9.9.46.1.6.1.1.19"   # 3072..4094

ADMIN_STATE_MAP = {"1": "up", "2": "down", "3": "testing"}
OPER_STATE_MAP = {
    "1": "up", "2": "down", "3": "testing", "4": "unknown",
    "5": "dormant", "6": "notPresent", "7": "lowerLayerDown",
}
DUPLEX_MAP = {"1": "unknown", "2": "half", "3": "full"}
VTP_STATE_MAP = {"1": "operational", "2": "suspended"}


def _bitmap_to_vlan_list(raw_value, base_vlan: int) -> list[int]:
    """Convert a VTP allowed-VLAN bitmap octet string into a list of VLAN IDs.

    The bitmap is big-endian: byte 0 bit 7 represents ``base_vlan + 0``, byte 0
    bit 6 ``base_vlan + 1`` and so on. Unknown/short bitmaps return [].
    """
    try:
        raw_bytes = bytes(raw_value)
    except Exception:
        return []
    vlans: list[int] = []
    for byte_idx, byte_val in enumerate(raw_bytes):
        for bit_idx in range(8):
            if byte_val & (0x80 >> bit_idx):
                vid = base_vlan + (byte_idx * 8) + bit_idx
                if 1 <= vid <= 4094:
                    vlans.append(vid)
    return vlans


def _format_ticks_to_iso_offset(ticks_raw) -> str:
    """ifLastChange is reported as TimeTicks since sysUpTime. Without the
    device's current sysUpTime + boot timestamp we can't convert to an
    absolute datetime here -- callers store the raw tick value and the
    audit rule does the relative-age math against a freshly walked
    sysUpTime. So we just normalise to a clean string."""
    try:
        return str(int(str(ticks_raw).strip()))
    except (ValueError, TypeError):
        return ""


async def collect_interface_inventory(host_id: int, ip_address: str,
                                       snmp_config: dict,
                                       timeout_seconds: float = 5.0) -> dict:
    """Walk per-port + VLAN-definition data for a single host.

    Writes to ``interface_inventory`` (one row per ifIndex) and
    ``vlan_definitions`` (one row per VLAN). Returns counts.
    """
    result = {"ports_written": 0, "vlans_written": 0, "errors": []}

    def _walk(oid: str, max_rows: int = 2500):
        return _snmp_walk(ip_address, timeout_seconds, snmp_config, oid, max_rows=max_rows)

    try:
        (if_names, if_descr, if_alias,
         admin_status, oper_status,
         high_speed, low_speed, last_change, duplex,
         vm_vlan, dot1q_pvid, bridge_port_map,
         vtp_names, vtp_states,
         trunk_vlans_1k, trunk_vlans_2k, trunk_vlans_3k, trunk_vlans_4k,
        ) = await asyncio.gather(
            _walk(IF_NAME_OID), _walk(IF_DESCR_OID), _walk(IF_ALIAS_OID),
            _walk(IF_ADMIN_STATUS_OID), _walk(IF_OPER_STATUS_OID),
            _walk(IF_HIGH_SPEED_OID), _walk(IF_SPEED_OID),
            _walk(IF_LAST_CHANGE_OID), _walk(DOT3_STATS_DUPLEX_OID),
            _walk(VM_VLAN_OID), _walk(DOT1Q_PVID_OID), _walk(DOT1D_BASE_PORT_IF_INDEX),
            _walk(VTP_VLAN_NAME_OID), _walk(VTP_VLAN_STATE_OID),
            _walk(VTP_TRUNK_VLANS_OID), _walk(VTP_TRUNK_VLANS_2K_OID),
            _walk(VTP_TRUNK_VLANS_3K_OID), _walk(VTP_TRUNK_VLANS_4K_OID),
        )
    except Exception as exc:
        result["errors"].append(f"SNMP walk failed: {str(exc)}")
        return result

    # ── Build ifIndex-keyed lookups ────────────────────────────────────
    def _idx_map(walk: dict[str, str]) -> dict[str, str]:
        out: dict[str, str] = {}
        for oid, val in walk.items():
            idx = oid.rsplit(".", 1)[-1] if "." in oid else ""
            if idx:
                out[idx] = _snmp_str(val)
        return out

    name_by_idx = _idx_map(if_names) or _idx_map(if_descr)
    descr_by_idx = _idx_map(if_descr)
    alias_by_idx = _idx_map(if_alias)
    admin_by_idx = _idx_map(admin_status)
    oper_by_idx = _idx_map(oper_status)
    hi_speed_by_idx = _idx_map(high_speed)
    lo_speed_by_idx = _idx_map(low_speed)
    last_change_by_idx = _idx_map(last_change)
    duplex_by_idx = _idx_map(duplex)
    vm_vlan_by_idx = _idx_map(vm_vlan)

    # dot1qPvid is indexed by dot1dBasePort -> translate to ifIndex
    bp_to_if_index: dict[str, str] = {}
    for oid, val in bridge_port_map.items():
        bp = oid.rsplit(".", 1)[-1] if "." in oid else ""
        if bp:
            bp_to_if_index[bp] = str(val).strip()

    pvid_by_if_index: dict[str, str] = {}
    for oid, val in dot1q_pvid.items():
        bp = oid.rsplit(".", 1)[-1] if "." in oid else ""
        if_idx = bp_to_if_index.get(bp)
        if if_idx:
            pvid_by_if_index[if_idx] = str(val).strip()

    # Trunk allowed-VLAN bitmaps: indexed by ifIndex. Stored as a comma-
    # delimited string for the audit rule -- compact and easy to diff.
    def _trunk_vlans_for_idx(if_idx: str) -> str:
        vlans: list[int] = []
        for walk, base in (
            (trunk_vlans_1k, 0),
            (trunk_vlans_2k, 1024),
            (trunk_vlans_3k, 2048),
            (trunk_vlans_4k, 3072),
        ):
            raw = None
            for oid, val in walk.items():
                if oid.rsplit(".", 1)[-1] == if_idx:
                    raw = val
                    break
            if raw is not None:
                vlans.extend(_bitmap_to_vlan_list(raw, base))
        # Deduplicate + sort. Trunk bitmaps frequently span all four
        # slices for fully-open trunks; keeping order stable makes diffs
        # of the inventory row readable.
        return ",".join(str(v) for v in sorted(set(vlans))) if vlans else ""

    # ── Resolve speed (Mbps) per ifIndex ──
    def _speed_mbps(if_idx: str) -> int:
        s = hi_speed_by_idx.get(if_idx, "")
        if s:
            try:
                return int(s)
            except (ValueError, TypeError) as exc:
                LOGGER.debug("interface_inventory: bad ifHighSpeed value %r for ifIndex %s: %s",
                             s, if_idx, exc)
        s2 = lo_speed_by_idx.get(if_idx, "")
        if s2:
            try:
                return max(0, int(s2) // 1_000_000)
            except (ValueError, TypeError) as exc:
                LOGGER.debug("interface_inventory: bad ifSpeed value %r for ifIndex %s: %s",
                             s2, if_idx, exc)
        return 0

    # ── Decide which VLAN to report for an access port ──
    def _access_vlan(if_idx: str) -> int:
        # vmVlan (Cisco) wins; dot1qPvid is a fallback. Trunks report a
        # vacuous PVID that we want to ignore, so an empty access_vlan
        # here is correct for them and the trunk_vlans column carries
        # the real info.
        for src in (vm_vlan_by_idx.get(if_idx, ""),
                    pvid_by_if_index.get(if_idx, "")):
            try:
                vid = int(src)
            except (ValueError, TypeError):
                continue
            if 1 <= vid <= 4094:
                return vid
        return 0

    # ── Write port rows ──
    all_if_indexes = set(name_by_idx) | set(admin_by_idx) | set(oper_by_idx)
    for if_idx in all_if_indexes:
        try:
            ifindex_int = int(if_idx)
        except (ValueError, TypeError):
            continue
        name = name_by_idx.get(if_idx) or descr_by_idx.get(if_idx) or f"ifIndex-{if_idx}"
        try:
            await db.upsert_interface_inventory(
                host_id=host_id,
                if_index=ifindex_int,
                name=name,
                description=alias_by_idx.get(if_idx, ""),
                admin_state=ADMIN_STATE_MAP.get(admin_by_idx.get(if_idx, ""), ""),
                oper_state=OPER_STATE_MAP.get(oper_by_idx.get(if_idx, ""), ""),
                speed_mbps=_speed_mbps(if_idx),
                duplex=DUPLEX_MAP.get(duplex_by_idx.get(if_idx, ""), ""),
                last_change=_format_ticks_to_iso_offset(last_change_by_idx.get(if_idx, "")),
                access_vlan=_access_vlan(if_idx),
                trunk_vlans=_trunk_vlans_for_idx(if_idx),
            )
            result["ports_written"] += 1
        except Exception as exc:
            LOGGER.warning("interface_inventory: host %s port upsert failed for ifIndex %s (%s): %s",
                           host_id, if_idx, name, exc)

    # ── Write VLAN definitions ──
    # vtpVlanName is indexed by <management-domain>.<vlan-id>; the trailing
    # numeric is the VLAN id. State map: 1=operational, 2=suspended, ...
    vlan_state_by_id: dict[int, str] = {}
    for oid, val in vtp_states.items():
        suffix = oid.rsplit(".", 1)[-1]
        try:
            vid = int(suffix)
        except (ValueError, TypeError):
            continue
        vlan_state_by_id[vid] = VTP_STATE_MAP.get(str(val).strip(), str(val).strip())

    for oid, val in vtp_names.items():
        suffix = oid.rsplit(".", 1)[-1]
        try:
            vid = int(suffix)
        except (ValueError, TypeError):
            continue
        if not (1 <= vid <= 4094):
            continue
        try:
            await db.upsert_vlan_definition(
                host_id=host_id,
                vlan_id=vid,
                name=_snmp_str(val),
                state=vlan_state_by_id.get(vid, "operational"),
            )
            result["vlans_written"] += 1
        except Exception as exc:
            LOGGER.warning("interface_inventory: host %s VLAN upsert failed for vlan %s: %s",
                           host_id, vid, exc)

    LOGGER.info(
        "interface_inventory: host %s (%s) - %d ports, %d VLANs collected",
        host_id, ip_address, result["ports_written"], result["vlans_written"],
    )
    return result


# ═════════════════════════════════════════════════════════════════════════════
# API Endpoints
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/api/mac-tracking/search")
async def search_mac(query: str = Query(""), limit: int = Query(5000, le=50000)):
    """Search across MAC/ARP tables by MAC address, IP, or port name.

    A blank query returns the most recently collected entries. The default
    limit is high enough to show the full table for typical deployments so
    the list doesn't silently truncate; the cap only guards pathological
    sizes.
    """
    return await db.search_mac_tracking(query, limit)


@router.get("/api/mac-tracking/stats")
async def mac_tracking_stats():
    """Header counts: total rows, unique MACs, switches reporting, freshness."""
    return await db.get_mac_tracking_stats()


@router.get("/api/mac-tracking/by-host")
async def mac_tracking_by_host():
    """Per-host collection rollup. Silent hosts (mac_count == 0) sort first.

    Each row is enriched with ``snmp_enabled`` resolved from the host's group
    so the UI can tell the difference between "host has no SNMP configured"
    and "host has SNMP configured but isn't returning FDB rows" — those are
    very different debugging paths.
    """
    from netcontrol.routes.state import _resolve_snmp_discovery_config

    rows = await db.get_mac_collection_by_host()
    # Cache the SNMP-enabled decision per group_id so we don't re-resolve for
    # every host in the same group.
    snmp_by_group: dict[int | None, bool] = {}
    for row in rows:
        gid = row.get("group_id")
        if gid not in snmp_by_group:
            try:
                cfg = _resolve_snmp_discovery_config(gid)
                snmp_by_group[gid] = bool(cfg.get("enabled"))
            except Exception:
                snmp_by_group[gid] = False
        row["snmp_enabled"] = snmp_by_group[gid]
    return rows


@router.get("/api/mac-tracking/host/{host_id}")
async def get_host_mac_arp(host_id: int):
    """Get MAC and ARP tables for a specific device."""
    macs = await db.get_mac_table_for_host(host_id)
    arps = await db.get_arp_table_for_host(host_id)
    return {"mac_table": macs, "arp_table": arps}


@router.get("/api/mac-tracking/history/{mac_address:path}")
async def get_mac_movement_history(mac_address: str, limit: int = Query(100, le=500)):
    """Get port movement history for a specific MAC address."""
    return await db.get_mac_history(mac_address, limit)


@router.get("/api/mac-tracking/port/{host_id}/{port_name:path}")
async def get_port_macs(host_id: int, port_name: str):
    """Get all MACs learned on a specific port."""
    return await db.get_macs_on_port(host_id, port_name)


# Guards against overlapping full-fleet collections. A full run walks every
# SNMP-enabled host and can take minutes (per-host VLAN budget is 60s), so a
# second concurrent run — an impatient double-click, or a manual run racing a
# scheduled one — would just double the device load for no benefit.
_full_collection_running = False


@router.post("/api/mac-tracking/collect")
async def trigger_mac_collection(host_id: int | None = Query(None)):
    """Trigger immediate MAC/ARP collection.
    If host_id is provided, collect from that host only.
    Otherwise, collect from all hosts with SNMP enabled.
    """
    global _full_collection_running
    from netcontrol.routes.state import _resolve_snmp_discovery_config

    if host_id is not None:
        host = await db.get_host(host_id)
        if not host:
            raise HTTPException(404, "Host not found")
        snmp_cfg = _resolve_snmp_discovery_config(host.get("group_id"))
        if not snmp_cfg.get("enabled"):
            raise HTTPException(400, "SNMP not enabled for this host's group")
        result = await collect_mac_arp_tables(
            host_id, host["ip_address"], snmp_cfg,
            device_type=host.get("device_type", ""),
            host=host,
        )
        result.setdefault("hosts_collected", 1)
        return result

    # Full-fleet collection. The check-then-set is atomic under asyncio (no
    # await between), so this reliably rejects a second concurrent run.
    if _full_collection_running:
        raise HTTPException(409, "A full MAC/ARP collection is already running")
    _full_collection_running = True
    try:
        # Flatten every SNMP-enabled host into one work list so the concurrency
        # cap stays saturated across the whole fleet instead of resetting per
        # group (one slow group no longer stalls the rest).
        targets: list[tuple[dict, dict]] = []
        for group in await db.get_all_groups():
            snmp_cfg = _resolve_snmp_discovery_config(group["id"])
            if not snmp_cfg.get("enabled"):
                continue
            for h in await db.get_hosts_for_group(group["id"]):
                targets.append((h, snmp_cfg))
    except Exception:
        _full_collection_running = False
        raise

    # A full run walks every SNMP-enabled host and can take minutes, so it
    # runs as a background job; the frontend polls the job endpoint below.
    # The runner clears _full_collection_running when it finishes.
    job = background_jobs.create_job(
        "mac-fleet-collection",
        {"hosts_done": 0, "hosts_total": len(targets)},
    )
    asyncio.create_task(_run_fleet_collection_job(job["job_id"], targets))
    return {"job_id": job["job_id"], "status": "running",
            "hosts_total": len(targets)}


async def _run_fleet_collection_job(job_id: str,
                                    targets: list[tuple[dict, dict]]) -> None:
    """Background task: collect MAC/ARP tables from every target host."""
    global _full_collection_running
    total: dict = {
        "macs_found": 0, "arps_found": 0, "hosts_collected": 0,
        "errors": [], "host_errors": [],
    }
    tasks: list[asyncio.Task] = []
    try:
        sem = asyncio.Semaphore(4)

        async def _collect_one(h: dict, cfg: dict) -> tuple[dict, dict | Exception]:
            async with sem:
                try:
                    res = await collect_mac_arp_tables(
                        h["id"], h["ip_address"], cfg,
                        device_type=h.get("device_type", ""),
                        host=h,
                    )
                except Exception as exc:
                    return h, exc
                return h, res

        tasks = [asyncio.create_task(_collect_one(h, cfg)) for h, cfg in targets]
        done = 0
        for coro in asyncio.as_completed(tasks):
            h, res = await coro
            done += 1
            hostname = h.get("hostname") or f"host-{h['id']}"
            if isinstance(res, Exception):
                total["errors"].append(f"{hostname}: {res}")
            else:
                total["macs_found"] += res["macs_found"]
                total["arps_found"] += res["arps_found"]
                total["hosts_collected"] += 1
                # Surface the per-host collection diagnostics that all-hosts
                # mode used to drop on the floor. These (per-VLAN budget hits,
                # view permission failures, "device isn't a bridge") are
                # exactly the signal the silent-host debugging workflow
                # depends on.
                host_errs = res.get("errors") or []
                if host_errs:
                    total["host_errors"].append({
                        "host_id": h["id"], "hostname": hostname,
                        "errors": host_errs,
                    })
                    for e in host_errs:
                        total["errors"].append(f"{hostname}: {e}")
            background_jobs.update_progress(
                job_id, hosts_done=done,
                macs_found=total["macs_found"], arps_found=total["arps_found"],
            )
        background_jobs.finish_job(job_id, "completed", result=total)
    except Exception as exc:
        LOGGER.exception("mac_tracking: fleet collection job %s failed", job_id)
        # Reap still-pending collectors so their results/exceptions are
        # consumed instead of warning "Task exception was never retrieved".
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        background_jobs.finish_job(job_id, "failed", result=total, error=str(exc))
    finally:
        _full_collection_running = False


@router.get("/api/mac-tracking/collect/jobs/{job_id}")
async def get_mac_collection_job(job_id: str):
    """Poll a fleet-collection job. Result carries the same aggregate payload
    the endpoint used to return inline (macs_found, arps_found,
    hosts_collected, errors, host_errors)."""
    job = background_jobs.get_job(job_id, kind="mac-fleet-collection")
    if job is None:
        raise HTTPException(404, "Collection job not found (it may have expired)")
    return job


@router.post("/api/mac-tracking/cleanup")
async def cleanup_stale_entries(days: int = Query(30, ge=1)):
    """Remove MAC entries not seen in the specified number of days."""
    removed = await db.cleanup_stale_mac_entries(days)
    return {"removed": removed}


# ═════════════════════════════════════════════════════════════════════════════
# MAC move events (drift-style change tracking)
# ═════════════════════════════════════════════════════════════════════════════


class MacMoveBulkAckRequest(BaseModel):
    event_ids: list[int] = []


@router.get("/api/mac-tracking/moves")
async def list_mac_move_events(
    status: str = Query("", pattern="^(open|acknowledged)?$"),
    host_id: int | None = Query(None),
    limit: int = Query(200, le=1000),
):
    """List MAC move events (newest first).

    Optionally filter by status, and by a switch "involved" in the move
    (matches either the from- or to-side host).
    """
    return await db.get_mac_move_events(status, limit, host_id=host_id)


@router.get("/api/mac-tracking/moves/summary")
async def mac_move_event_summary():
    """Open / acknowledged / total counts for the summary cards."""
    return await db.get_mac_move_event_summary()


@router.get("/api/mac-tracking/moves/{event_id}/history")
async def mac_move_event_history(event_id: int, limit: int = Query(500, le=1000)):
    """Lifecycle timeline (detected, acknowledged) for one move event."""
    return await db.get_mac_move_event_history(event_id, limit)


@router.post("/api/mac-tracking/moves/{event_id}/acknowledge")
async def acknowledge_mac_move_event(event_id: int, request: Request):
    """Acknowledge a single open move event."""
    session = _get_session(request)
    user = session["user"] if session else ""
    ok = await db.acknowledge_mac_move_event(event_id, actor=user)
    if not ok:
        raise HTTPException(404, "Move event not found")
    await _audit(
        "mac-tracking", "move.acknowledged", user=user,
        detail=f"event_id={event_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.post("/api/mac-tracking/moves/acknowledge-all")
async def acknowledge_all_mac_move_events(
    body: MacMoveBulkAckRequest, request: Request
):
    """Acknowledge every open move event (or a specific list of ids)."""
    session = _get_session(request)
    user = session["user"] if session else ""
    if body.event_ids:
        acked = 0
        for eid in body.event_ids:
            if await db.acknowledge_mac_move_event(eid, actor=user):
                acked += 1
        await _audit(
            "mac-tracking", "move.acknowledged_bulk", user=user,
            detail=f"acknowledged={acked} of {len(body.event_ids)} requested ids",
            correlation_id=_corr_id(request),
        )
        return {"ok": True, "acknowledged": acked}
    acked = await db.acknowledge_open_mac_move_events(actor=user)
    await _audit(
        "mac-tracking", "move.acknowledged_all", user=user,
        detail=f"acknowledged={acked} open events",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "acknowledged": acked}


# ═════════════════════════════════════════════════════════════════════════════
# Scheduled retention
# ═════════════════════════════════════════════════════════════════════════════


async def _run_mac_move_retention_once() -> dict:
    """Prune MAC move events and movement-history rows past the retention window."""
    days = int(state.MAC_MOVE_RETENTION_CONFIG.get(
        "event_retention_days",
        state.MAC_MOVE_RETENTION_DEFAULTS["event_retention_days"]))
    removed = 0
    history_removed = 0
    try:
        removed = await db.delete_old_mac_move_events(days)
    except Exception as exc:
        LOGGER.warning("mac move retention failed: %s", exc)
    # The movement-history log grows independently of the events (it gets a row
    # on every per-switch relocation), so prune it on the same window — without
    # this it grew unbounded.
    try:
        history_removed = await db.delete_old_mac_history(days)
    except Exception as exc:
        LOGGER.warning("mac history retention failed: %s", exc)
    if removed or history_removed:
        LOGGER.info("mac move retention: pruned %d events, %d history rows older than %d days",
                    removed, history_removed, days)
    return {"removed": removed, "history_removed": history_removed, "retention_days": days}


async def _mac_move_retention_loop() -> None:
    """Infinite loop that prunes old MAC move events at a fixed interval."""
    while True:
        try:
            await asyncio.sleep(int(state.MAC_MOVE_RETENTION_CONFIG.get(
                "interval_seconds",
                state.MAC_MOVE_RETENTION_DEFAULTS["interval_seconds"])))
            await _run_mac_move_retention_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("mac move retention loop failure: %s", exc)
            await asyncio.sleep(
                state.MAC_MOVE_RETENTION_DEFAULTS["interval_seconds"])
