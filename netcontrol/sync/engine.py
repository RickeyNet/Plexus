"""The diff engine and the plan.

``diff_records`` pairs the records of the remote system with Plexus's by
natural key and lists, per pair, the fields whose normalised values differ
(only fields both sides read are compared). ``plan_entries`` turns that diff
into ``Entry`` objects for a job's direction:

- ``import`` (remote -> Plexus): remote-only records are created in Plexus,
  differing fields are written to Plexus; with ``delete_missing`` the
  Plexus-only records are deleted.
- ``export`` (Plexus -> remote): the mirror image.
- ``bidirectional``: records missing on either side are created there; a
  field empty on one side is filled from the other; a field with two
  different values is a conflict, settled by the conflict policy
  (``source_wins``: the remote value is written to Plexus; ``plexus_wins``:
  Plexus's value is written to the remote; ``skip_conflicts``: a
  ``conflict`` entry that changes nothing). Bidirectional runs never delete:
  without a baseline a missing record cannot be told from a new one.

Fields the target cannot write (``writable``) are left out of its entries.
A delete wave larger than ``MAX_DELETE_SHARE`` of the target's records (and
more than ``MIN_DELETES_GUARDED``) is held back: its entries are skipped.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from netcontrol.sync.models import SyncRecord, key_text, spec_for

MAX_DELETE_SHARE = 0.5
MIN_DELETES_GUARDED = 10


@dataclass
class DiffItem:
    object_type: str
    key: tuple[str, ...]
    label: str
    remote: SyncRecord | None
    plexus: SyncRecord | None
    # field -> (remote value, Plexus value), differing fields only.
    fields: dict[str, tuple[str, str]] = field(default_factory=dict)

    @property
    def state(self) -> str:
        if self.plexus is None:
            return "remote_only"
        if self.remote is None:
            return "plexus_only"
        return "changed" if self.fields else "same"


@dataclass
class DiffResult:
    items: list[DiffItem]
    # Records sharing a key with an earlier one on the same side (ignored).
    duplicates: list[str] = field(default_factory=list)

    def count(self, state: str) -> int:
        return sum(1 for item in self.items if item.state == state)


def _index(records: Iterable[SyncRecord], side: str, duplicates: list[str]) -> dict[tuple[str, ...], SyncRecord]:
    out: dict[tuple[str, ...], SyncRecord] = {}
    for record in records:
        key = record.key
        if not key[0]:
            continue
        if key in out:
            duplicates.append(f"{side} has more than one {record.spec.label} {record.label!r}; the first is used.")
            continue
        out[key] = record
    return out


def diff_records(
    object_type: str,
    remote: Iterable[SyncRecord],
    plexus: Iterable[SyncRecord],
    fields: Iterable[str],
) -> DiffResult:
    """Pair the two sides by natural key and diff the ``fields`` both read."""
    spec = spec_for(object_type)
    compared = [f for f in fields if f in spec.fields and f not in spec.key]
    duplicates: list[str] = []
    remote_by_key = _index(remote, "The remote system", duplicates)
    plexus_by_key = _index(plexus, "Plexus", duplicates)
    items: list[DiffItem] = []
    for key in sorted(set(remote_by_key) | set(plexus_by_key)):
        r, p = remote_by_key.get(key), plexus_by_key.get(key)
        label = key_text(spec, (r or p).values)  # type: ignore[union-attr]
        item = DiffItem(object_type, key, label, r, p)
        if r is not None and p is not None:
            for name in compared:
                if name in r.values and name in p.values and r.values[name] != p.values[name]:
                    item.fields[name] = (r.values[name], p.values[name])
        items.append(item)
    return DiffResult(items, duplicates)


# ── Plan ─────────────────────────────────────────────────────────────────────


@dataclass
class Entry:
    """One planned change and, after a run, its outcome. ``changes`` is
    ``{field: {"before", "after"}}`` on the target (for a conflict
    ``{field: {"plexus", "remote"}}``); ``values`` what a create or update
    writes (key fields always included); ``ref`` the target's handle of the
    record for an update or delete."""

    object_type: str
    key: str
    action: str
    target: str
    changes: dict[str, dict[str, str]] = field(default_factory=dict)
    values: dict[str, str] = field(default_factory=dict)
    ref: Any = None
    outcome: str = "planned"
    message: str = ""

    def applied(self, message: str = "") -> None:
        self.outcome, self.message = "applied", message

    def failed(self, message: str) -> None:
        self.outcome, self.message = "failed", message

    def skipped(self, message: str) -> None:
        self.outcome, self.message = "skipped", message

    def as_dict(self) -> dict[str, Any]:
        return {
            "object_type": self.object_type,
            "key": self.key,
            "action": self.action,
            "target": self.target,
            "changes": self.changes,
            "outcome": self.outcome,
            "message": self.message,
        }


def _create(item: DiffItem, source: SyncRecord, target: str, writable: set[str]) -> Entry:
    spec = spec_for(item.object_type)
    values = {k: v for k, v in source.values.items() if k in spec.key or k in writable}
    changes = {k: {"before": "", "after": v} for k, v in values.items() if v}
    entry = Entry(item.object_type, item.label, "create", target, changes, values)
    # A key field the target cannot write blocks the create unless it is
    # empty (a global prefix on a system without VRFs).
    blocked = [k for k in spec.key if k not in writable and values.get(k)]
    if blocked:
        entry.skipped(f"The {target} side cannot write the key field(s) {', '.join(blocked)}.")
    return entry


def _update(item: DiffItem, target: str, new: dict[str, tuple[str, str]], ref: Any) -> Entry:
    """``new``: field -> (before on the target, after)."""
    spec = spec_for(item.object_type)
    base = item.remote if target == "plexus" else item.plexus
    values = {k: (base.values.get(k, "") if base else "") for k in spec.key}
    values.update({k: after for k, (_before, after) in new.items()})
    changes = {k: {"before": before, "after": after} for k, (before, after) in new.items()}
    return Entry(item.object_type, item.label, "update", target, changes, values, ref)


def _delete(item: DiffItem, record: SyncRecord, target: str) -> Entry:
    changes = {k: {"before": v, "after": ""} for k, v in record.values.items() if v}
    return Entry(item.object_type, item.label, "delete", target, changes, dict(record.values), record.ref)


def plan_entries(
    diff: DiffResult,
    *,
    direction: str,
    policy: str = "skip_conflicts",
    delete_missing: bool = False,
    writable_plexus: set[str],
    writable_remote: set[str],
) -> list[Entry]:
    """The entries a run applies (unchanged records have none)."""
    entries: list[Entry] = []
    for item in diff.items:
        r, p = item.remote, item.plexus
        if r is not None and p is None:
            if direction in ("import", "bidirectional"):
                entries.append(_create(item, r, "plexus", writable_plexus))
            elif direction == "export" and delete_missing:
                entries.append(_delete(item, r, "remote"))
            continue
        if p is not None and r is None:
            if direction in ("export", "bidirectional"):
                entries.append(_create(item, p, "remote", writable_remote))
            elif direction == "import" and delete_missing:
                entries.append(_delete(item, p, "plexus"))
            continue
        if not item.fields or r is None or p is None:
            continue
        to_plexus: dict[str, tuple[str, str]] = {}
        to_remote: dict[str, tuple[str, str]] = {}
        conflicts: dict[str, dict[str, str]] = {}
        for name, (rv, pv) in item.fields.items():
            if direction == "import":
                to_plexus[name] = (pv, rv)
            elif direction == "export":
                to_remote[name] = (rv, pv)
            elif not pv:
                to_plexus[name] = (pv, rv)
            elif not rv:
                to_remote[name] = (rv, pv)
            elif policy == "source_wins":
                to_plexus[name] = (pv, rv)
            elif policy == "plexus_wins":
                to_remote[name] = (rv, pv)
            else:
                conflicts[name] = {"plexus": pv, "remote": rv}
        to_plexus = {k: v for k, v in to_plexus.items() if k in writable_plexus}
        to_remote = {k: v for k, v in to_remote.items() if k in writable_remote}
        if to_plexus:
            entries.append(_update(item, "plexus", to_plexus, p.ref))
        if to_remote:
            entries.append(_update(item, "remote", to_remote, r.ref))
        if conflicts:
            conflict = Entry(item.object_type, item.label, "conflict", "plexus", conflicts)
            conflict.skipped("Both sides changed; the job skips conflicts.")
            entries.append(conflict)
    _guard_deletes(entries, diff)
    return entries


def _guard_deletes(entries: list[Entry], diff: DiffResult) -> None:
    for target in ("plexus", "remote"):
        deletes = [e for e in entries if e.action == "delete" and e.target == target]
        if len(deletes) <= MIN_DELETES_GUARDED:
            continue
        held = sum(1 for i in diff.items if (i.plexus if target == "plexus" else i.remote) is not None)
        if held and len(deletes) / held > MAX_DELETE_SHARE:
            for entry in deletes:
                entry.skipped(
                    f"Held back: the run would delete {len(deletes)} of {held} records on the {target} side "
                    f"(more than {int(MAX_DELETE_SHARE * 100)}%). Check the mapping and the remote filter."
                )


def summarise(entries: Iterable[Entry], diff: DiffResult) -> dict[str, int]:
    """Counts for a run summary: records per state and entries per action
    and outcome."""
    out = {
        "remote_records": sum(1 for i in diff.items if i.remote is not None),
        "plexus_records": sum(1 for i in diff.items if i.plexus is not None),
        "unchanged": diff.count("same"),
        "create": 0,
        "update": 0,
        "delete": 0,
        "conflict": 0,
        "planned": 0,
        "applied": 0,
        "failed": 0,
        "skipped": 0,
    }
    for entry in entries:
        out[entry.action] += 1
        out[entry.outcome] += 1
    return out
