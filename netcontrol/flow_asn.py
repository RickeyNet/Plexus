"""Optional offline GeoLite2 ASN enrichment for ranked flow addresses."""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Iterable
from ipaddress import IPv6Address, ip_address
from pathlib import Path
from stat import S_ISREG
from threading import Lock
from time import monotonic
from typing import TypedDict

import maxminddb

LOGGER = logging.getLogger("plexus.flow_asn")
_RECHECK_SECONDS = 60


class FlowAsn(TypedDict):
    asn: int
    asn_organization: str | None


def _record(reader: maxminddb.Reader, ip: str) -> FlowAsn | None:
    try:
        addr = ip_address(ip)
        if isinstance(addr, IPv6Address):
            if addr.scope_id is not None:
                return None
            addr = addr.ipv4_mapped or addr
        if not addr.is_global or addr.is_multicast or addr.is_reserved:
            return None
        record = reader.get(addr)
    except ValueError, maxminddb.InvalidDatabaseError:
        return None
    if not isinstance(record, dict):
        return None
    asn = record.get("autonomous_system_number")
    if type(asn) is not int or not 0 < asn < 2**32:
        return None
    name = record.get("autonomous_system_organization")
    return {"asn": asn, "asn_organization": (name.strip() or None) if isinstance(name, str) else None}


class AsnDatabase:
    """Keep one in-memory reader and reload it when the updater replaces the file."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = Lock()
        self._reader: maxminddb.Reader | None = None
        self._file_version: tuple[int, int, int, int, int] | None = None
        self._next_check = 0.0

    def _refresh(self) -> None:
        now = monotonic()
        if now < self._next_check:
            return
        self._next_check = now + _RECHECK_SECONDS
        try:
            stat = self._path.stat()
            if not S_ISREG(stat.st_mode):
                return
            version = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
            if version == self._file_version:
                return
            # Remember unreadable/invalid versions too, so every dashboard
            # refresh doesn't reload and re-log the same bad file.
            self._file_version = version
            # Do not hold a file/mmap open: the updater needs to replace it,
            # and the last good in-memory reader survives a bad replacement.
            candidate = maxminddb.open_database(self._path, maxminddb.MODE_MEMORY)
            if candidate.metadata().database_type != "GeoLite2-ASN":
                candidate.close()
                raise maxminddb.InvalidDatabaseError("expected a GeoLite2-ASN database")
        except FileNotFoundError:
            self._file_version = None
            return
        except (OSError, ValueError, maxminddb.InvalidDatabaseError) as exc:
            if isinstance(exc, OSError):
                self._file_version = None  # Retry transient I/O failures.
            LOGGER.warning("Could not load the GeoLite2 ASN database: %s", exc)
            return

        if self._reader is not None:
            self._reader.close()
        self._reader = candidate

    def lookup(self, ips: Iterable[str]) -> dict[str, FlowAsn]:
        # Serialize reload/close and lookups across to_thread workers.
        with self._lock:
            self._refresh()
            if self._reader is None:
                return {}
            return {ip: record for ip in set(ips) if (record := _record(self._reader, ip)) is not None}


_path = os.environ.get("APP_FLOW_ASN_DB", "").strip()
_database = AsnDatabase(Path(_path)) if _path else None


async def lookup_flow_asns(ips: list[str]) -> dict[str, FlowAsn]:
    if _database is None or not ips:
        return {}
    return await asyncio.to_thread(_database.lookup, ips)
