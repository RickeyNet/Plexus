"""AWS as a vendor alert feed provider (current state, polled).

Registered with ``netcontrol.routes.vendor_alerts`` (which runs the poll,
the store, the alerting and the API). Each enabled AWS account of Cloud
Visibility is read with the credentials its discovery uses
(``cloud_metric_pullers._build_boto3_session``: the stored keys, profile
or the server's own credentials, then the IAM role when one is set), in
every region of its scope (``all`` lists the enabled regions), every
``interval_seconds`` (300 by default), each blocking boto3 call in a worker
thread:

- ``cloudwatch``: ``DescribeAlarms`` with ``StateValue=ALARM`` per region.
- ``ec2_status``: ``DescribeInstanceStatus`` per region (running instances).
- ``health``: ``DescribeEvents`` and ``DescribeAffectedEntities`` once per
  account, signed for ``us-east-1``. Without a Business support plan or
  higher AWS answers ``SubscriptionRequiredException``: the account then
  shows "AWS Health needs a Business support plan or higher", the Health
  part is not asked again for ``HEALTH_RETRY_HOURS`` (kept in the feed's
  cursor) and the other parts go on.

Each region and part is one scope of ``cloud_alert_feeds.ScopeRun``: read in
full, its alerts are the complete open set and the ones it no longer
reports resolve; a failed region resolves nothing and is shown as a note.
The mapping lives in ``netcontrol.integrations.aws.alerts``; see
``docs/cloud-alerts.md``.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable
from typing import Any

from netcontrol.integrations.aws import alerts as aws
from netcontrol.integrations.cloud_alerts import scope_prefix
from netcontrol.routes import cloud_alert_feeds as cloud, vendor_alerts
from netcontrol.routes.cloud_collectors import (
    CloudCollectorUnavailable,
    _aws_call,
    _parse_auth_config,
    aws_credential_message,
    provider_error_detail,
)
from netcontrol.routes.meraki_topology import PROVIDER_AWS

# How long a Health refusal (no support plan) holds before asking again.
HEALTH_RETRY_HOURS = 24
_ACCESS_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "UnrecognizedClientException",
    "InvalidClientTokenId",
    "AuthFailure",
    "SignatureDoesNotMatch",
    "OptInRequired",
}
_THROTTLE_CODES = {"Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyRequestsException"}


def _require_sdk() -> None:
    """Raise ``CloudCollectorUnavailable`` when boto3 is not installed."""
    try:
        import boto3  # noqa: F401
    except ImportError as exc:
        raise CloudCollectorUnavailable("The AWS alert feed requires boto3") from exc


def _session(auth: dict):
    """The boto3 session of an account (blocking: may assume a role)."""
    from netcontrol.routes.cloud_metric_pullers import _build_boto3_session

    return _build_boto3_session(auth)


def _regions(account: dict, session) -> list[str]:
    from netcontrol.routes.cloud_metric_pullers import _resolve_regions

    return _resolve_regions(account, session)


def _client(session, service: str, region: str):
    from netcontrol.routes.cloud_metric_pullers import _boto3_client_config

    return session.client(service, region_name=region, config=_boto3_client_config())


def _error_code(exc: BaseException) -> str:
    response = getattr(exc, "response", None)
    error = response.get("Error") if isinstance(response, dict) else None
    return str((error or {}).get("Code") or "") if isinstance(error, dict) else ""


def pages(client, operation: str, token_in: str, token_out: str, **kwargs: Any) -> tuple[list[dict], bool]:
    """At most ``MAX_API_PAGES`` pages of one call (blocking), and whether
    that was all of them."""
    found: list[dict] = []
    token = ""
    for _ in range(cloud.MAX_API_PAGES):
        args = dict(kwargs)
        if token:
            args[token_in] = token
        answer = _aws_call(client, operation, **args)
        found.append(answer)
        token = str(answer.get(token_out) or "")
        if not token:
            return found, True
    return found, False


def read_alarms(session, region: str) -> tuple[dict, bool]:
    """The alarms in ALARM of a region, the pages merged."""
    answers, complete = pages(
        _client(session, "cloudwatch", region), "describe_alarms", "NextToken", "NextToken", **aws.DESCRIBE_ALARMS_ARGS
    )
    merged: dict[str, list] = {"MetricAlarms": [], "CompositeAlarms": []}
    for answer in answers:
        for name in merged:
            merged[name] += answer.get(name) or []
    return merged, complete


def read_instance_status(session, region: str) -> tuple[list[dict], bool]:
    answers, complete = pages(
        _client(session, "ec2", region),
        "describe_instance_status",
        "NextToken",
        "NextToken",
        MaxResults=aws.INSTANCE_STATUS_MAX_RESULTS,
    )
    return [s for a in answers for s in a.get("InstanceStatuses") or []], complete


def read_health(session) -> tuple[list[dict], list[dict], bool]:
    """The open and upcoming Health events and their affected entities."""
    client = _client(session, "health", aws.HEALTH_REGION)
    answers, complete = pages(
        client,
        "describe_events",
        "nextToken",
        "nextToken",
        filter=aws.HEALTH_EVENT_FILTER,
        maxResults=aws.HEALTH_MAX_RESULTS,
    )
    events = [e for a in answers for e in a.get("events") or []]
    arns = [str(e["arn"]) for e in events if isinstance(e, dict) and e.get("arn")]
    entities: list[dict] = []
    step = aws.HEALTH_ENTITY_ARNS_PER_CALL
    for start in range(0, len(arns), step):
        found, whole = pages(
            client,
            "describe_affected_entities",
            "nextToken",
            "nextToken",
            filter={"eventArns": arns[start : start + step]},
            maxResults=aws.HEALTH_MAX_RESULTS,
        )
        entities += [e for a in found for e in a.get("entities") or []]
        # Affected entities read in part only name fewer resources.
        complete = complete and whole
    return events, entities, complete


async def read_pages(source: dict, cursor: str, max_pages: int) -> AsyncIterator[vendor_alerts.FeedPage]:
    """One poll of one account: a page per region and part (see the module
    docstring). ``max_pages`` does not apply: the reads are bounded per
    scope (``cloud_alert_feeds.MAX_API_PAGES``)."""
    account = await cloud.load_account(PROVIDER_AWS, source)
    _require_sdk()
    auth = _parse_auth_config(account)
    session = await asyncio.to_thread(_session, auth)
    regions = await asyncio.to_thread(_regions, account, session)
    index = await cloud.tracked_index(PROVIDER_AWS)
    run = cloud.ScopeRun(PROVIDER_AWS, account, cloud.load_state(cursor))
    name = str(account.get("name") or "")
    account_id = int(account["id"])
    now = cloud.now_text()

    def on(part: str) -> bool:
        return vendor_alerts.part_enabled(PROVIDER_AWS, part)

    for part in (aws.PART_CLOUDWATCH, aws.PART_EC2, aws.PART_HEALTH):
        if not on(part):
            yield run.disabled(part)
    if regions:
        # A region taken out of the account's scope is read no more: its
        # open alerts resolve.
        gone = await cloud.dropped_scopes(PROVIDER_AWS, account_id, (aws.PART_CLOUDWATCH, aws.PART_EC2), regions)
        if gone:
            yield vendor_alerts.FeedPage(cursor=run.cursor(), complete_scopes=gone)
    for region in regions:
        if on(aws.PART_CLOUDWATCH):
            label = f"CloudWatch alarms in {region}"
            try:
                answer, complete = await asyncio.to_thread(read_alarms, session, region)
            except Exception as exc:  # noqa: BLE001 - one region never hides the others
                run.fail(label, exc)
            else:
                found = aws.alarm_events(account_id, name, region, answer, index)
                scope = scope_prefix(aws.PROVIDER, account_id, aws.PART_CLOUDWATCH, region)
                yield run.page(scope, found, complete=complete, label=label)
        if on(aws.PART_EC2):
            label = f"EC2 instance status in {region}"
            try:
                statuses, complete = await asyncio.to_thread(read_instance_status, session, region)
            except Exception as exc:  # noqa: BLE001
                run.fail(label, exc)
            else:
                found, unknown = aws.instance_status_events(account_id, name, region, statuses, index, now)
                scope = scope_prefix(aws.PROVIDER, account_id, aws.PART_EC2, region)
                yield run.page(scope, found, complete=complete, unknown=unknown, label=label)
    if on(aws.PART_HEALTH):
        async for page in _health(run, session, account_id, name, regions, index, now):
            yield page
    yield run.last()


async def _health(
    run: cloud.ScopeRun, session, account_id: int, name: str, regions: list[str], index: dict, now: str
) -> AsyncIterator[vendor_alerts.FeedPage]:
    """The Health part, unless AWS refused it for want of a support plan
    within ``HEALTH_RETRY_HOURS``."""
    if str(run.state.get("health_refused_until") or "") > now:
        run.note(aws.HEALTH_PLAN_NOTE)
        return
    try:
        events, entities, complete = await asyncio.to_thread(read_health, session)
    except Exception as exc:  # noqa: BLE001
        if _error_code(exc) == aws.HEALTH_PLAN_CODE:
            run.state["health_refused_until"] = cloud.later_text(HEALTH_RETRY_HOURS)
            run.note(aws.HEALTH_PLAN_NOTE)
        else:
            run.fail("AWS Health", exc)
        return
    run.state.pop("health_refused_until", None)
    found = aws.health_events(account_id, name, regions, events, entities, index)
    yield run.page(
        scope_prefix(aws.PROVIDER, account_id, aws.PART_HEALTH), found, complete=complete, label="AWS Health"
    )


def describe_error(exc: Exception) -> vendor_alerts.FeedError:
    """What a failed poll tells the administrator (never a credential)."""
    if isinstance(exc, CloudCollectorUnavailable):
        return vendor_alerts.FeedError(
            "boto3 is not installed on the Plexus server (requirements-cloud.txt)", "error", access=True
        )
    credentials = aws_credential_message(exc)
    if credentials:
        return vendor_alerts.FeedError(credentials, "no_access", access=True)
    code = _error_code(exc)
    detail = provider_error_detail(exc)
    if code in _ACCESS_CODES or code.endswith("AccessDenied"):
        return vendor_alerts.FeedError(f"AWS refused the request: {detail}", "no_access", access=True)
    if code in _THROTTLE_CODES:
        return vendor_alerts.FeedError("AWS rate limit: retried later", "rate_limited")
    if "EndpointConnectionError" in type(exc).__name__ or "ConnectTimeout" in type(exc).__name__:
        return vendor_alerts.FeedError("Could not reach the AWS API", "unreachable")
    return vendor_alerts.FeedError(f"AWS error: {detail}", "error")


def _sources() -> Awaitable[list[dict[str, Any]]]:
    return cloud.cloud_sources(PROVIDER_AWS)


PROVIDER = vendor_alerts.FeedProvider(
    provider=PROVIDER_AWS,
    label="AWS alerts",
    feed="current_state",
    list_sources=_sources,
    read_pages=read_pages,
    describe_error=describe_error,
    description=(
        "CloudWatch alarms in ALARM state, AWS Health issues and scheduled changes, and impaired EC2 status "
        "checks and scheduled events of each AWS account of Cloud Visibility, read with the account's discovery "
        "credentials. An alert resolves when the next complete read no longer reports it."
    ),
    current_state=True,
    defaults=cloud.CLOUD_DEFAULTS,
    parts=aws.PARTS,
)
vendor_alerts.register(PROVIDER)
