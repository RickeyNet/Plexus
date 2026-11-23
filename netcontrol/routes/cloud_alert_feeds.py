"""What the AWS and Azure alert feed providers share
(``netcontrol.routes.aws_alerts``, ``netcontrol.routes.azure_alerts``):
their sources (the enabled Cloud Visibility accounts of the cloud, not the
demo ones), the account re-read at each poll, the tracked entities of the
cloud, the small state kept in the feed's cursor, and :class:`ScopeRun`,
which turns the reads of one poll into pipeline pages.

Both are *current-state* feeds of ``netcontrol.routes.vendor_alerts``: each
scope read in full is a page that declares its key prefix complete, so an
alert the read no longer reports resolves; a scope that failed is a note
on the source's status and resolves nothing; when every scope failed the
poll fails and backs off like any feed. A part switched off in the feed's
settings is declared complete with no alerts, so its open alerts resolve.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import routes.database as db

from netcontrol.integrations.cloud_alerts import entity_index, scope_prefix
from netcontrol.routes import vendor_alerts
from netcontrol.routes.cloud_collectors import provider_error_detail
from netcontrol.routes.meraki_topology import _CLOUD_BY_PROVIDER

# Bound on the API pages read per scope and poll. A scope with more is read
# in part: its alerts are stored, none of the scope is resolved.
MAX_API_PAGES = 10
# The default interval of the cloud feeds: every five minutes (ARM reads are
# throttled per subscription, CloudWatch DescribeAlarms per region and
# account; see docs/cloud-alerts.md).
CLOUD_DEFAULTS: dict[str, Any] = {"interval_seconds": 300}
_FMT = "%Y-%m-%d %H:%M:%S"


def now_text() -> str:
    return datetime.now(UTC).strftime(_FMT)


def later_text(hours: float) -> str:
    return (datetime.now(UTC) + timedelta(hours=hours)).strftime(_FMT)


def tracker_org_ref(provider: str) -> int:
    """The ``org_ref`` the availability tracker files a cloud's entities
    under (every account of the cloud shares it): the alerts carry it, so
    mutes, host matching and the no-double-notification rule apply."""
    return int(_CLOUD_BY_PROVIDER[provider].org_ref)


async def cloud_sources(provider: str) -> list[dict]:
    """The accounts of a cloud the feed polls: enabled, not the demo
    accounts. Credentials are not part of a source (re-read at each poll)."""
    return [
        {"id": int(a["id"]), "name": str(a.get("name") or ""), "has_api_key": True}
        for a in await db.list_cloud_accounts(provider=provider, enabled_only=True)
        if a.get("auth_type") != "sample"
    ]


async def load_account(provider: str, source: dict) -> dict:
    """The account of a source, with its decrypted auth config."""
    account = await db.get_cloud_account(int(source["id"]))
    if not account or str(account.get("provider") or "") != provider or not account.get("enabled"):
        raise vendor_alerts.FeedError("The account was removed or disabled", "error", access=True)
    return account


async def tracked_index(provider: str) -> dict[str, dict]:
    """The cloud's tracked devices and services, by entity id."""
    try:
        return entity_index(await db.list_topology_entity_states(provider, tracker_org_ref(provider)))
    except Exception as exc:  # noqa: BLE001 - alerts are still stored, as account-level ones
        vendor_alerts.LOGGER.warning("alert feeds: %s tracked entities not read: %s", provider, type(exc).__name__)
        return {}


async def dropped_scopes(provider: str, account_id: int, parts: tuple[str, ...], current: list[str]) -> list[str]:
    """The scope prefixes of ``parts`` that still hold open alerts and are
    not among the ``current`` scopes of the account (a region taken out of
    its region scope): nothing reads them any more, so the caller declares
    them complete and their alerts resolve."""
    found: set[str] = set()
    for part in parts:
        prefix = scope_prefix(provider, account_id, part)
        for key in await db.list_open_vendor_alert_keys(provider, prefix):
            scope = key[len(prefix) :].partition(":")[0]
            if scope and scope not in current:
                found.add(scope_prefix(provider, account_id, part, scope))
    return sorted(found)


def load_state(cursor: str) -> dict[str, Any]:
    """The state a cloud feed keeps in its cursor (JSON), ``{}`` if none."""
    try:
        found = json.loads(cursor or "{}")
    except TypeError, ValueError:
        return {}
    return found if isinstance(found, dict) else {}


class ScopeRun:
    """The pages of one poll of one account: :meth:`page` for a scope read
    in full or in part, :meth:`disabled` for a part switched off,
    :meth:`fail` for a scope that failed, :meth:`note` for what to show;
    :meth:`last` is the final page, or raises when every scope failed."""

    def __init__(self, provider: str, account: dict, state: dict[str, Any]) -> None:
        self.provider = provider
        self.account_id = int(account["id"])
        self.org_ref = tracker_org_ref(provider)
        self.state = state
        self.notes: list[str] = []
        self.failures: list[tuple[str, Exception]] = []
        self.done = 0

    def cursor(self) -> str:
        return json.dumps(self.state, sort_keys=True)

    def note(self, text: str) -> None:
        if text and text not in self.notes:
            self.notes.append(text)

    def page(
        self, scope: str, alerts: list[dict], *, complete: bool, unknown: list[str] | None = None, label: str = ""
    ) -> vendor_alerts.FeedPage:
        """A scope read: its alerts (filed under the tracker's org_ref) and,
        when read in full, its prefix declared complete."""
        self.done += 1
        if not complete:
            # More than MAX_API_PAGES pages, or a next page on another host.
            self.note(f"{label}: read in part (nothing resolved)")
        return vendor_alerts.FeedPage(
            cursor=self.cursor(),
            alerts=[{**a, "org_ref": self.org_ref} for a in alerts],
            records=len(alerts),
            complete_scopes=[scope] if complete else [],
            unknown_keys=list(unknown or []),
        )

    def disabled(self, part: str) -> vendor_alerts.FeedPage:
        """A part switched off: its open alerts resolve."""
        return vendor_alerts.FeedPage(
            cursor=self.cursor(), complete_scopes=[scope_prefix(self.provider, self.account_id, part)]
        )

    def fail(self, label: str, exc: Exception) -> None:
        self.failures.append((label, exc))
        self.note(f"{label}: {provider_error_detail(exc)}"[:300])

    def last(self) -> vendor_alerts.FeedPage:
        """The final page, with the notes. Every scope failed: the first
        error is raised (the poll fails and backs off)."""
        if self.failures and not self.done:
            raise self.failures[0][1]
        return vendor_alerts.FeedPage(cursor=self.cursor(), notes=list(self.notes))
