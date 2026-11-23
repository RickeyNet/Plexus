"""Azure as a vendor alert feed provider (current state, polled).

Registered with ``netcontrol.routes.vendor_alerts`` (which runs the poll,
the store, the alerting and the API). Each enabled Azure account of Cloud
Visibility (one subscription) is read every ``interval_seconds`` (300 by
default) over plain Azure Resource Manager REST calls
(``https://management.azure.com``), with a token for
``https://management.azure.com/.default`` from the credential the discovery
builds (``cloud_collectors.build_azure_credential``: its service principal,
else ``DefaultAzureCredential``), sent through the project's outbound HTTP
sender (``outbound_http.send_request``: SSRF guard, pinned address, no
redirects). A ``nextLink`` is followed only to the same ARM host.

- ``monitor_alerts``: the subscription's fired Azure Monitor alerts.
- ``resource_health``: the subscription's Resource Health availability
  statuses (``Unavailable`` / ``Degraded`` alert; ``Unknown`` is left as it
  is; ``Available`` resolves).

Each part is one scope of ``cloud_alert_feeds.ScopeRun`` (see there). The
mapping lives in ``netcontrol.integrations.azure.alerts``; see
``docs/cloud-alerts.md``. Public Azure cloud only (sovereign clouds have
other ARM hosts).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any
from urllib.parse import urlsplit

import httpx

from netcontrol.integrations.azure import alerts as azure
from netcontrol.integrations.cloud_alerts import scope_prefix
from netcontrol.routes import cloud_alert_feeds as cloud, vendor_alerts
from netcontrol.routes.cloud_collectors import (
    CloudCollectorUnavailable,
    _parse_auth_config,
    build_azure_credential,
    provider_error_detail,
)
from netcontrol.routes.meraki_topology import PROVIDER_AZURE
from netcontrol.routes.outbound_http import OutboundRequestError, send_request

_TIMEOUT_SECONDS = 30.0
# Injectable for tests: the HTTP sender and the token source.
_SEND: Callable[..., Awaitable[httpx.Response]] = send_request


class ArmError(Exception):
    """An ARM call that failed: its HTTP status (``None``: not reached) and
    ARM's error code and message."""

    def __init__(self, status: int | None, code: str = "", message: str = "") -> None:
        super().__init__(f"{code}: {message}" if code else (message or f"HTTP {status}"))
        self.status = status
        self.code = code
        # The shape ``provider_error_detail`` reads.
        self.response = {"Error": {"Code": code or f"HTTP {status}", "Message": message}}


def _token(auth: dict) -> str:
    """An ARM access token (blocking). ``CloudCollectorUnavailable``
    without azure-identity."""
    try:
        credential = build_azure_credential(auth)
    except ImportError as exc:
        raise CloudCollectorUnavailable("The Azure alert feed requires azure-identity") from exc
    return str(credential.get_token(azure.ARM_SCOPE).token)


async def arm_list(token: str, path: str) -> tuple[list[dict], bool]:
    """The ``value`` items of an ARM list, at most
    ``cloud_alert_feeds.MAX_API_PAGES`` pages, and whether that was all."""
    url = f"https://{azure.ARM_HOST}{path}"
    items: list[dict] = []
    for _ in range(cloud.MAX_API_PAGES):
        try:
            response = await _SEND(
                "GET",
                url,
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                timeout_s=_TIMEOUT_SECONDS,
            )
        except httpx.HTTPError as exc:
            raise ArmError(None, "", type(exc).__name__) from exc
        if response.status_code >= 300:
            code, message = _arm_error(response)
            raise ArmError(response.status_code, code, message)
        try:
            body = response.json()
        except ValueError as exc:
            raise ArmError(response.status_code, "", "the answer is not JSON") from exc
        items += [v for v in (body.get("value") or []) if isinstance(v, dict)] if isinstance(body, dict) else []
        link = str(body.get("nextLink") or "") if isinstance(body, dict) else ""
        if not link:
            return items, True
        parts = urlsplit(link)
        if parts.scheme != "https" or (parts.hostname or "").lower() != azure.ARM_HOST:
            # Never sent elsewhere with the token: read in part.
            return items, False
        url = link
    return items, False


def _arm_error(response: httpx.Response) -> tuple[str, str]:
    try:
        error = (response.json() or {}).get("error") or {}
    except ValueError, AttributeError:
        error = {}
    if not isinstance(error, dict):
        return "", ""
    return str(error.get("code") or "")[:80], " ".join(str(error.get("message") or "").split())[:300]


async def read_pages(source: dict, cursor: str, max_pages: int) -> AsyncIterator[vendor_alerts.FeedPage]:
    """One poll of one subscription: a page per part. ``max_pages`` does not
    apply: the reads are bounded per part (``MAX_API_PAGES``)."""
    account = await cloud.load_account(PROVIDER_AZURE, source)
    auth = _parse_auth_config(account)
    subscription = str(auth.get("subscription_id") or account.get("account_identifier") or "").strip()
    if not subscription:
        raise vendor_alerts.FeedError("Set the Azure subscription ID of this account", "error", access=True)
    token = await asyncio.to_thread(_token, auth)
    index = await cloud.tracked_index(PROVIDER_AZURE)
    run = cloud.ScopeRun(PROVIDER_AZURE, account, cloud.load_state(cursor))
    name = str(account.get("name") or "")
    account_id = int(account["id"])
    now = cloud.now_text()
    for part, path, label in (
        (azure.PART_MONITOR, azure.alerts_path(subscription), "Azure Monitor alerts"),
        (azure.PART_HEALTH, azure.resource_health_path(subscription), "Resource Health"),
    ):
        if not vendor_alerts.part_enabled(PROVIDER_AZURE, part):
            yield run.disabled(part)
            continue
        try:
            items, complete = await arm_list(token, path)
        except ArmError as exc:  # one part never hides the other
            run.fail(label, exc)
            continue
        unknown: list[str] = []
        if part == azure.PART_MONITOR:
            found = azure.monitor_alert_events(account_id, name, subscription, items, index)
        else:
            found, unknown = azure.resource_health_events(account_id, name, subscription, items, index, now)
        scope = scope_prefix(azure.PROVIDER, account_id, part)
        yield run.page(scope, found, complete=complete, unknown=unknown, label=label)
    yield run.last()


def describe_error(exc: Exception) -> vendor_alerts.FeedError:
    """What a failed poll tells the administrator (never a credential)."""
    if isinstance(exc, CloudCollectorUnavailable):
        return vendor_alerts.FeedError(
            "azure-identity is not installed on the Plexus server (requirements-cloud.txt)", "error", access=True
        )
    if isinstance(exc, ArmError):
        detail = provider_error_detail(exc)
        if exc.status in (401, 403):
            return vendor_alerts.FeedError(f"Azure refused the request: {detail}", "no_access", access=True)
        if exc.status == 429:
            return vendor_alerts.FeedError("Azure Resource Manager throttled the reads: retried later", "rate_limited")
        if exc.status is None:
            return vendor_alerts.FeedError("Could not reach Azure Resource Manager", "unreachable")
        return vendor_alerts.FeedError(f"Azure error: {detail}", "error")
    if isinstance(exc, OutboundRequestError):
        return vendor_alerts.FeedError(f"The outbound request was refused: {exc}", "error", access=True)
    if "Authentication" in type(exc).__name__ or "Credential" in type(exc).__name__:
        return vendor_alerts.FeedError(f"Azure sign-in failed: {provider_error_detail(exc)}", "no_access", access=True)
    return vendor_alerts.FeedError(f"Azure error: {provider_error_detail(exc)}", "error")


def _sources() -> Awaitable[list[dict[str, Any]]]:
    return cloud.cloud_sources(PROVIDER_AZURE)


PROVIDER = vendor_alerts.FeedProvider(
    provider=PROVIDER_AZURE,
    label="Azure alerts",
    feed="current_state",
    list_sources=_sources,
    read_pages=read_pages,
    describe_error=describe_error,
    description=(
        "Fired Azure Monitor alerts (the alert rules defined in the subscription) and Resource Health "
        "availability (a resource Unavailable or Degraded) of each Azure subscription of Cloud Visibility, read "
        "with the subscription's discovery credentials. An alert resolves when the next complete read no longer "
        "reports it."
    ),
    current_state=True,
    defaults=cloud.CLOUD_DEFAULTS,
    parts=azure.PARTS,
)
vendor_alerts.register(PROVIDER)
