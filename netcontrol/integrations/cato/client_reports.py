"""Cato Client connection reports - what each remote user's Client applied.

``collect_client_reports`` reads, with a :class:`CatoClient`, the latest
**Client Connectivity Policy** event of every remote user's device from
Cato's ``events`` query and returns the *raw* rows; :class:`ClientReports`
indexes them for the normalizer, which shows a user's report in a "Client
report" section and uses it to settle the user's Split Tunnel rule.

Why: a Split Tunnel rule may name a source network ("Any managed network",
"Any unmanaged network"). Cato's public API has no query for the managed
network definitions, and the account snapshot has no per-user flag saying
whether the device is on one, so such a rule cannot be decided from
configuration. The Client, however, reports the Split Tunnel configuration
it applied each time it connects: that report is the collected fact.

What is read (one query, paged):

  ``events(accountID, timeFrame: "last.P7D", filters, dimensions, measures,
  sort) { from to totalCount records(limit, from) { fieldsMap } }``

  - filters: ``event_type is "Connectivity"`` and ``event_sub_type is
    "Client Connectivity Policy"`` (the event a Client's connection emits
    when its Client Connectivity Policy is evaluated)
  - dimensions (``DIMENSIONS``): user id and name, device name, OS, the
    Split Tunnel configuration the Client applied ("Disabled", "Admin
    Defined", "User Defined"), Office Mode, Trusted Networks (Managed
    Networks, whether that feature is on for the connection), the public IP
    the Client connects from and the PoP. A row is one group per distinct
    combination of these, and an event lacking any of them is left out by
    Cato, so only fields every such event carries are named
  - measures: ``event_count`` summed, and the newest ``time`` as ``last_time``
  - sort: ``last_time`` newest first; pages of ``PAGE_SIZE`` groups, at most
    ``MAX_PAGES`` pages (a note records the groups not read)

The rows are reduced to one per (user id, device name): the newest. Cato
returns ``last_time`` as ``"2026-10-26 19:51:37.014"`` (UTC, no zone), as
``"2026-10-26T19:00"`` with fewer dimensions, or as epoch milliseconds;
``parse_time`` reads all three and stores ``YYYY-MM-DDTHH:MM:SSZ``.

The query is ``@ga``; the API key needs the View permission for events.
Failure policy: best-effort. A refusal is recorded in ``errors`` and the
payload is ``None`` - not collected - while ``{"rows": []}`` means read and
none found.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from netcontrol.integrations.cato.client import CatoApiError, CatoClient, error_entry, note_entry
from netcontrol.integrations.cato.site_config import _int as _count
from netcontrol.integrations.meraki.collector import scrub_secrets
from netcontrol.integrations.meraki.compliance import _parse_iso
from netcontrol.integrations.meraki.normalize import _s, kv_section

PHASE = "cato client reports"
PATH = "events (Client Connectivity Policy)"
OPERATION = "plexusClientReports"
TIME_FRAME = "last.P7D"
PAGE_SIZE = 1000
MAX_PAGES = 10

DIMENSIONS = (
    "user_id",
    "user_name",
    "device_name",
    "os_type",
    "split_tunnel_configuration",
    "office_mode",
    "trusted_networks",
    "src_ip",
    "pop_name",
)

QUERY = """
query plexusClientReports(
  $accountID: ID!, $timeFrame: TimeFrame!, $filters: [EventsFilter!], $dimensions: [EventsDimension],
  $measures: [EventsMeasure], $sort: [EventsSort!], $limit: Int, $from: Int
) {
  events(
    accountID: $accountID, timeFrame: $timeFrame, measures: $measures, dimensions: $dimensions,
    filters: $filters, sort: $sort
  ) {
    from
    to
    totalCount
    records(limit: $limit, from: $from) { fieldsMap }
  }
}
"""

Report = Callable[..., None]


def query_variables(account_id: str, offset: int = 0) -> dict[str, Any]:
    """The variables of one page of ``QUERY``."""
    return {
        "accountID": account_id,
        "timeFrame": TIME_FRAME,
        "filters": [
            {"fieldName": "event_type", "operator": "is", "values": ["Connectivity"]},
            {"fieldName": "event_sub_type", "operator": "is", "values": ["Client Connectivity Policy"]},
        ],
        "dimensions": [{"fieldName": name} for name in DIMENSIONS],
        "measures": [
            {"fieldName": "event_count", "aggType": "sum"},
            {"fieldName": "time", "aggType": "max", "alias": "last_time"},
        ],
        "sort": [{"alias": "last_time", "order": "desc"}],
        "limit": PAGE_SIZE,
        "from": offset,
    }


def parse_time(value: Any) -> str:
    """An event time as ``YYYY-MM-DDTHH:MM:SSZ`` (UTC); ``""`` when it cannot
    be read. Epoch milliseconds, ISO text with or without a zone, and the
    ``"2026-10-26 19:51:37.014"`` spelling Cato uses (UTC, no zone)."""
    if value is None or isinstance(value, bool):
        return ""
    text = str(value).strip()
    found: datetime | None
    if text.isdigit():
        try:
            found = datetime.fromtimestamp(int(text) / 1000, tz=UTC)
        except OverflowError, OSError, ValueError:
            return ""
    else:
        found = _parse_iso(text.replace(" ", "T", 1))
        if found is None:
            return ""
        found = found.replace(tzinfo=UTC) if found.tzinfo is None else found.astimezone(UTC)
    return found.strftime("%Y-%m-%dT%H:%M:%SZ")


def time_text(stamp: Any) -> str:
    """``2026-10-26T12:39:02Z`` as ``2026-10-26 12:39:02 UTC``, for sentences."""
    text = _s(stamp).strip()
    if text.endswith("Z") and "T" in text:
        return f"{text[:-1].replace('T', ' ', 1)} UTC"
    return text or "an unknown time"


def _row(fields: dict) -> dict[str, Any]:
    """One group of ``fieldsMap`` as a stored row."""
    row: dict[str, Any] = {name: _s(fields.get(name)).strip() for name in DIMENSIONS}
    row["time"] = parse_time(fields.get("last_time", fields.get("time")))
    row["event_count"] = _count(fields.get("event_count"))
    return row


def reduce_rows(rows: list[dict]) -> list[dict]:
    """One row per (user id, device name): the newest. Newest first."""
    newest: dict[tuple[str, str], dict] = {}
    for row in rows:
        if not row.get("user_id"):
            continue
        key = (row["user_id"], row.get("device_name", "").lower())
        if key not in newest or row.get("time", "") > newest[key].get("time", ""):
            newest[key] = row
    return sorted(newest.values(), key=lambda r: (r.get("time", ""), r["user_id"]), reverse=True)


async def collect_client_reports(
    client: CatoClient,
    account_id: str,
    errors: list[dict[str, Any]],
    report: Report | None = None,
) -> dict[str, Any] | None:
    """``{"from", "to", "rows"}``: the latest Client Connectivity Policy
    report of every user device in the last 7 days, or ``None`` when Cato
    refused the query (recorded in ``errors``). Never raises.

    ``report(phase, calls=n, planned=m)`` is called with the queries
    finished since the previous call and the queries added to the plan (one
    is planned up front; each page after the first adds one)."""

    def progress(calls: int = 0, planned: int = 0) -> None:
        if report is not None:
            report(PHASE, calls=calls, planned=planned)

    progress()
    rows: list[dict] = []
    window: dict[str, str] = {"from": "", "to": ""}
    read = total = 0
    for page in range(MAX_PAGES):
        if page:
            progress(planned=1)
        try:
            data = await client.query(OPERATION, QUERY, query_variables(account_id, read))
        except CatoApiError as exc:
            progress(calls=1)
            errors.append(error_entry("account", PATH, exc))
            return None
        progress(calls=1)
        found = data.get("events")
        events: dict[str, Any] = found if isinstance(found, dict) else {}
        if not page:
            window = {key: parse_time(events.get(key)) or _s(events.get(key)) for key in ("from", "to")}
        records = [r for r in events.get("records") or [] if isinstance(r, dict)]
        read += len(records)
        total = max(_count(events.get("totalCount")), read)
        rows += [_row(r["fieldsMap"]) for r in records if isinstance(r.get("fieldsMap"), dict)]
        if not records or read >= total:
            break
    if total > read:
        errors.append(
            note_entry(
                "account",
                PATH,
                f"First {read} of {total} report groups read ({MAX_PAGES} pages of {PAGE_SIZE}, newest first); "
                f"the rest were not read",
            )
        )
    return {**window, "rows": scrub_secrets(reduce_rows(rows))}


# ── Lookup ────────────────────────────────────────────────────────────────────

NOT_COLLECTED = "not collected"
NOT_FOUND = "not found for this device"


def describe(row: dict) -> tuple[str, str, str]:
    """``(Split Tunnel value, device, time)`` of a report, for sentences."""
    return (
        _s(row.get("split_tunnel_configuration")).strip(),
        _s(row.get("device_name")).strip() or "an unnamed device",
        time_text(row.get("time")),
    )


class ClientReports:
    """The rows of ``collect_client_reports`` by user id, newest first."""

    def __init__(self, payload: Any) -> None:
        rows = payload.get("rows") if isinstance(payload, dict) else None
        self.collected = isinstance(rows, list)
        self._by_user: dict[str, list[dict]] = {}
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict) and _s(row.get("user_id")).strip():
                self._by_user.setdefault(_s(row.get("user_id")).strip(), []).append(row)
        for found in self._by_user.values():
            found.sort(key=lambda r: _s(r.get("time")), reverse=True)

    def for_user(self, user_id: Any, device_name: Any) -> tuple[dict | None, bool]:
        """``(row, current)``: the newest report for the user's current
        device (``current`` true), else the newest for the user from another
        device (``current`` false), else ``(None, False)``."""
        rows = self._by_user.get(_s(user_id).strip(), [])
        device = _s(device_name).strip().lower()
        mine = next((r for r in rows if device and _s(r.get("device_name")).strip().lower() == device), None)
        if mine is not None:
            return mine, True
        return (rows[0], False) if rows else (None, False)

    @property
    def missing(self) -> str:
        """Why a user has no usable report: ``NOT_COLLECTED`` or ``NOT_FOUND``."""
        return NOT_FOUND if self.collected else NOT_COLLECTED

    def section(self, user_id: Any, device_name: Any) -> dict | None:
        """The "Client report" section of a user's node."""
        if not self.collected:
            return kv_section("Client report", [("Reports", "Not collected")])
        row, current = self.for_user(user_id, device_name)
        if row is None:
            return kv_section("Client report", [("Reports", "No Client Connectivity Policy event in the last 7 days")])
        rows: list[tuple[str, Any]] = [
            ("Reported", time_text(row.get("time"))),
            ("Device", row.get("device_name")),
            ("OS", row.get("os_type")),
            ("Split Tunnel", row.get("split_tunnel_configuration")),
            ("Office Mode", row.get("office_mode")),
            ("Managed Networks (Trusted Networks)", row.get("trusted_networks")),
            ("Public IP", row.get("src_ip")),
            ("PoP", row.get("pop_name")),
        ]
        if not current:
            connected = _s(device_name).strip()
            where = f"the one connected now ({connected})" if connected else "the one connected now (not named)"
            rows.append(("Note", f"From another device than {where}: not used for the Split Tunnel decision"))
        return kv_section("Client report", rows)
