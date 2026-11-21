"""Traffic rates of topology entities: the readings and the counter store.

A tunnel's traffic is read from the cumulative byte counters its vendor
reports (``netcontrol.integrations.traffic``). Two kinds of reading feed
the same store of last readings (``routes.db.topology_traffic``):

  - a stored collection (``record_collection_traffic``, called by
    ``meraki_topology._store_snapshot`` before the snapshot is saved): its
    rates go on the snapshot (the items' ``metrics`` and "Traffic"
    sections), from where availability tracking stores them with the
    collection's other measurements; it names the tracked entity of every
    key and drops the keys a clean collection no longer reports;
  - a monitoring poll of an inventory host that is an OPNsense firewall
    (``record_poll_traffic``, from ``netcontrol.routes.opnsense_health``),
    every few minutes: it reads the VPN counters only and writes ``in_bps``
    / ``out_bps`` samples under the entity the last collection named for
    each key (a key no collection has named yet is left out).

Each reading computes the rate since the last reading of its key and then
replaces it, under a lock per source, so collections and polls interleave
with one sample per reading and no overlap. A reading older than the
stored one never replaces it.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import routes.database as db

from netcontrol.integrations.availability import clean_entity_types, extract_entity_states
from netcontrol.integrations.traffic import apply_traffic_rates, rate_since, reading_time, store_time, traffic_items
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.topology_traffic")

_LOCKS: dict[tuple[str, int], asyncio.Lock] = {}


def _lock(provider: str, org_ref: int) -> asyncio.Lock:
    return _LOCKS.setdefault((str(provider), int(org_ref)), asyncio.Lock())


async def record_collection_traffic(provider: str, org_ref: int, snapshot: dict) -> int:
    """Compute the rates of a collection's ``traffic`` blocks against the
    store, put them on ``snapshot`` and store its readings. Returns how
    many rates were computed. Never raises (a failure leaves the snapshot
    without rates)."""
    items = traffic_items(snapshot)
    # Only a collection that read everything proves a key is gone.
    prune = "tunnel" in clean_entity_types(provider, snapshot)
    if not items and not prune:
        return 0
    try:
        async with _lock(provider, org_ref):
            at = reading_time(snapshot) or datetime.now(UTC)
            previous = await db.get_topology_traffic_counters(provider, org_ref) if items else {}
            computed = apply_traffic_rates(snapshot, previous, at)
            entities = {
                str(e.meta["traffic_key"]): e
                for e in extract_entity_states(provider, org_ref, snapshot)
                if e.meta.get("traffic_key")
            }
            readings = [
                {
                    "key": key,
                    "entity_type": entities[key].entity_type,
                    "entity_id": entities[key].entity_id,
                    "counters": item["traffic"].get("counters"),
                }
                for item in items
                if (key := str(item["traffic"].get("key") or "")) in entities
            ]
            await db.save_topology_traffic_counters(provider, org_ref, readings, store_time(at), replace=prune)
            return computed
    except Exception as exc:  # noqa: BLE001 - the collection is stored without rates
        LOGGER.warning("topology traffic: %s org %s not recorded: %s", provider, org_ref, type(exc).__name__)
        return 0


async def record_poll_traffic(provider: str, org_ref: int, blocks: dict[str, dict], at: datetime) -> int:
    """Store the rates of a poll's ``traffic`` blocks (by key, read at
    ``at``) against the store, and its readings. Only keys the store knows
    (a collection named their entity) are used. Returns the samples
    written."""
    async with _lock(provider, org_ref):
        previous = await db.get_topology_traffic_counters(provider, org_ref)
        samples: list[dict] = []
        readings: list[dict] = []
        for key, block in blocks.items():
            last = previous.get(key)
            if last is None or not last["entity_id"]:
                continue
            rates, _reason, _elapsed = rate_since(last, block, at)
            if rates is not None:
                samples.append({"entity_type": last["entity_type"], "entity_id": last["entity_id"], "metrics": rates})
            readings.append(
                {
                    "key": key,
                    "entity_type": last["entity_type"],
                    "entity_id": last["entity_id"],
                    "counters": block.get("counters"),
                }
            )
        written = 0
        if samples:
            written = await db.record_topology_entity_metrics(provider, org_ref, samples, now=store_time(at))
        if readings:
            await db.save_topology_traffic_counters(provider, org_ref, readings, store_time(at))
        return written
