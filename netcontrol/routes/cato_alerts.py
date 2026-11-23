"""The Cato events feed as a vendor alert feed provider.

Registered with ``netcontrol.routes.vendor_alerts`` (which runs the poll, the
store, the alerting and the API). Each Cato source (a topology source with
provider ``cato``, an account ID and an API key; not a demo entry) is read
with ``eventsFeed`` through the shared Cato client (``CatoClient``: its URL
validation, pacing and rate-limit retry), from the marker stored for it, at
most ``vendor_alerts.MAX_PAGES_PER_POLL`` pages per poll. The first read
of a source has no marker: Cato then answers its current position in the
queue (and maybe no events), so enabling the feed never replays the queue's
three days. The mapping of events lives in
``netcontrol.integrations.cato.events_feed``; see ``docs/cato-alerts.md``.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator

import httpx
import routes.database as db

from netcontrol.integrations.cato import events_feed
from netcontrol.integrations.cato.client import DEFAULT_BASE_URL, CatoApiError, CatoClient
from netcontrol.routes import vendor_alerts
from netcontrol.routes.meraki_topology import PROVIDER_CATO, _is_demo, _provider_of

# Injectable for tests (``httpx.MockTransport``).
_TRANSPORT: httpx.AsyncBaseTransport | None = None
_TIMEOUT_SECONDS = 20.0
_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_ACCESS_WORDS = ("permission", "not authorized", "unauthorized", "forbidden", "access denied", "not enabled")


async def cato_sources() -> list[dict]:
    """The Cato accounts that can be polled: provider ``cato``, an account
    ID, not a demo entry."""
    return [
        org
        for org in await db.list_meraki_orgs()
        if _provider_of(org) == PROVIDER_CATO and str(org.get("org_id") or "").strip() and not _is_demo(org)
    ]


async def read_pages(source: dict, cursor: str, max_pages: int) -> AsyncIterator[vendor_alerts.FeedPage]:
    """The feed of one account from ``cursor``: one page per ``eventsFeed``
    call, until a call returns no records or ``max_pages``."""
    account = str(source.get("org_id") or "").strip()
    if not _ACCOUNT_RE.match(account):
        raise vendor_alerts.FeedError("Set a valid Cato account ID on this source", "error", access=True)
    api_key = await db.get_meraki_org_api_key(int(source["id"]))
    if not api_key:
        raise vendor_alerts.FeedError("No API key is stored for this source", "no_access", access=True)
    org_name = str(source.get("name") or "")
    async with CatoClient(
        api_key,
        base_url=str(source.get("base_url") or "") or DEFAULT_BASE_URL,
        timeout=_TIMEOUT_SECONDS,
        max_retries=1,
        transport=_TRANSPORT,
    ) as client:
        for _ in range(max(1, int(max_pages))):
            data = await client.query("plexusEventsFeed", events_feed.EVENTS_FEED_QUERY, events_feed.variables(account, cursor))
            page = events_feed.parse_page(data)
            if page["errors"]:
                # Cato's own words, e.g. the events feed is not enabled.
                raise vendor_alerts.FeedError(
                    "Cato refused the events feed: " + "; ".join(page["errors"])[:400], "refused", access=True
                )
            found = events_feed.classify(page["records"], org_ref=int(source["id"]), org_name=org_name)
            times = [t for t in (events_feed.event_time(r) for r in page["records"]) if t]
            next_cursor = page["marker"] or cursor
            yield vendor_alerts.FeedPage(
                cursor=next_cursor,
                alerts=found["alerts"],
                security=found["security"],
                records=len(page["records"]),
                last_event_at=max(times, default=""),
            )
            if not page["records"] or not cursor or next_cursor == cursor:
                # No more for now; a first read only positions the marker.
                return
            cursor = next_cursor


def describe_error(exc: Exception) -> vendor_alerts.FeedError:
    """What a failed read tells the administrator (never the API key)."""
    if isinstance(exc, CatoApiError):
        detail = str(exc.detail or "")[:300]
        if exc.status_code in (401, 403):
            return vendor_alerts.FeedError(f"Cato rejected the API key (HTTP {exc.status_code})", "no_access", access=True)
        if exc.graphql:
            lowered = detail.lower()
            if "rate limit" in lowered or "too many requests" in lowered:
                return vendor_alerts.FeedError("Cato rate limit: retried later", "rate_limited")
            access = any(word in lowered for word in _ACCESS_WORDS)
            return vendor_alerts.FeedError(
                f"Cato refused the events feed: {detail}" if detail else "Cato refused the events feed",
                "refused",
                access=access,
            )
        if exc.status_code == 429:
            return vendor_alerts.FeedError("Cato rate limit: retried later", "rate_limited")
        if exc.status_code is None:
            return vendor_alerts.FeedError("Could not reach the Cato API", "unreachable")
        return vendor_alerts.FeedError(f"Cato API error (HTTP {exc.status_code})", "error")
    if isinstance(exc, ValueError):
        return vendor_alerts.FeedError("The Cato API URL of this source is not valid", "error", access=True)
    return vendor_alerts.FeedError(type(exc).__name__, "error")


PROVIDER = vendor_alerts.FeedProvider(
    provider=PROVIDER_CATO,
    label="Cato events feed",
    feed=events_feed.FEED,
    list_sources=cato_sources,
    read_pages=read_pages,
    describe_error=describe_error,
    description=(
        "Site, link and Socket connectivity events and IPS events from each Cato account's events feed "
        "(eventsFeed). The events feed must be enabled for the account in the Cato management application."
    ),
)
vendor_alerts.register(PROVIDER)
