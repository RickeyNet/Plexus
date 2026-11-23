"""AWS alerts for the vendor alert feed (``netcontrol.routes.aws_alerts``):
the mapping of CloudWatch alarms, AWS Health events and EC2 instance status
to alert events. Pure: the provider makes the calls (boto3) and hands the
answers here; the tests hand the invented answers of ``aws.sample``.

Sources, with the AWS API reference each field is read from:

- **CloudWatch alarms** (``cloudwatch:DescribeAlarms``, per region, with
  ``StateValue=ALARM`` and ``AlarmTypes`` ``MetricAlarm`` and
  ``CompositeAlarm``; ``MaxRecords`` 1 to 100, ``NextToken`` paging).
  Response ``MetricAlarms`` / ``CompositeAlarms``; per alarm ``AlarmName``,
  ``AlarmArn``, ``AlarmDescription``, ``StateValue`` (``OK`` / ``ALARM`` /
  ``INSUFFICIENT_DATA``), ``StateReason`` (an explanation of the state, in
  text), ``StateTransitionedTimestamp`` (when ``StateValue`` last changed),
  ``StateUpdatedTimestamp``, and for a metric alarm ``Namespace``,
  ``MetricName``, ``Dimensions`` (``Name`` / ``Value``) or, for a metric
  math alarm, ``Metrics[].MetricStat.Metric.Dimensions``. Log alarms
  (``LogAlarm``) are not read. An alarm carries no severity: see
  :func:`alarm_severity`.
- **AWS Health** (``health:DescribeEvents`` with ``eventStatusCodes``
  ``open`` / ``upcoming`` and ``eventTypeCategories`` ``issue`` /
  ``scheduledChange``; ``maxResults`` 1 to 100, ``nextToken`` paging; then
  ``health:DescribeAffectedEntities`` for at most 10 event ARNs per call).
  Event fields: ``arn``, ``service``, ``eventTypeCode``,
  ``eventTypeCategory`` (``issue`` / ``accountNotification`` /
  ``scheduledChange`` / ``investigation``), ``region``, ``startTime``,
  ``endTime``, ``lastUpdatedTime``, ``statusCode`` (``open`` / ``closed`` /
  ``upcoming``), ``eventScopeCode`` (``PUBLIC`` / ``ACCOUNT_SPECIFIC`` /
  ``NONE``). Affected entity fields: ``eventArn``, ``entityValue`` (the
  ID of the affected entity, such as an instance ID), ``entityArn``,
  ``statusCode`` (``IMPAIRED`` / ``UNIMPAIRED`` / ``UNKNOWN`` / ``PENDING``
  / ``RESOLVED``). The API needs a Business, Enterprise On-Ramp or
  Enterprise support plan (or their successors) and answers
  ``SubscriptionRequiredException`` otherwise (``HEALTH_PLAN_NOTE``).
- **EC2 instance status** (``ec2:DescribeInstanceStatus``, per region;
  running instances only by default; ``MaxResults`` / ``NextToken``).
  Per instance ``InstanceId``, ``SystemStatus`` and ``InstanceStatus``
  (``Status``: ``ok`` / ``impaired`` / ``initializing`` /
  ``insufficient-data`` / ``not-applicable``; ``Details[].ImpairedSince``),
  ``AttachedEbsStatus`` (same vocabulary) and ``Events`` (scheduled events:
  ``Code`` ``instance-reboot`` / ``system-reboot`` / ``system-maintenance`` /
  ``instance-retirement`` / ``instance-stop``, ``Description``, which
  starts with ``[Completed]`` once the event is done, ``NotBefore``,
  ``NotAfter``, ``InstanceEventId``).

Each alert names the tracked entity of the resource when the topology
availability tracker follows it (``cloud_alerts.match_entity``: an
instance is the device ``i:<id>``, a Transit Gateway ``tgw:<id>``...; a
managed service its resource uid), else it is an account-level alert.
"""

from __future__ import annotations

import re
from typing import Any

from netcontrol.integrations.cloud_alerts import (
    alert_event,
    key_part,
    match_entity,
    scope_prefix,
    service_match,
    text,
    utc_text,
)

PROVIDER = "aws"
PART_CLOUDWATCH = "cloudwatch"
PART_HEALTH = "health"
PART_EC2 = "ec2_status"
PARTS: tuple[tuple[str, str], ...] = (
    (PART_CLOUDWATCH, "CloudWatch alarms in ALARM state"),
    (PART_HEALTH, "AWS Health issues and scheduled changes (Business support plan or higher)"),
    (PART_EC2, "EC2 instance status checks and scheduled events"),
)
# The region the AWS Health API is signed for (its active endpoint in the
# commercial partition, ``health.us-east-1.amazonaws.com``).
HEALTH_REGION = "us-east-1"
HEALTH_PLAN_CODE = "SubscriptionRequiredException"
HEALTH_PLAN_NOTE = "AWS Health needs a Business support plan or higher"

DESCRIBE_ALARMS_ARGS: dict[str, Any] = {
    "StateValue": "ALARM",
    "AlarmTypes": ["MetricAlarm", "CompositeAlarm"],
    "MaxRecords": 100,
}
HEALTH_EVENT_FILTER: dict[str, Any] = {
    "eventStatusCodes": ["open", "upcoming"],
    "eventTypeCategories": ["issue", "scheduledChange"],
}
HEALTH_MAX_RESULTS = 100
HEALTH_ENTITY_ARNS_PER_CALL = 10
INSTANCE_STATUS_MAX_RESULTS = 1000
# Affected entities kept per Health event: one alert each when tracked, the
# others listed in the event's alert.
MAX_ENTITIES_PER_EVENT = 20

# Snapshot node ids of the AWS resources the map draws as devices
# (``aws.normalize``): ``i:<instance id>``, ``tgw:<transit gateway id>``...
_DEVICE_PREFIXES = ("i", "igw", "nat", "vgw", "tgw", "dx", "dxgw", "cgw")
_CRITICAL_RE = re.compile(r"\bcritical\b", re.IGNORECASE)
_REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d+$")
_OPEN_ENTITY_STATES = ("IMPAIRED", "PENDING", "UNKNOWN", "")
_DONE_PREFIXES = ("[completed]", "[canceled]", "[cancelled]")


def candidates(value: Any) -> list[str]:
    """The entity ids a resource id or ARN may have on the map: the device
    node ids of the id and of the last part of an ARN
    (``arn:...:instance/i-0abc`` -> ``i-0abc``)."""
    raw = text(value, 1600)
    if not raw:
        return []
    ids = [raw]
    tail = raw.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
    if tail and tail != raw:
        ids.append(tail)
    return [f"{prefix}:{rid}" for rid in ids for prefix in _DEVICE_PREFIXES]


def resource_entity(index: dict[str, dict], value: Any) -> dict | None:
    """The tracked entity a resource id, ARN or name stands for: a device
    node, else a managed service whose resource uid ends with it."""
    found = match_entity(index, candidates(value))
    if found is not None:
        return found
    raw = text(value, 1600)
    tail = raw.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
    return service_match(index, PROVIDER, raw) or (service_match(index, PROVIDER, tail) if tail != raw else None)


# ── CloudWatch alarms ────────────────────────────────────────────────────────


def alarm_severity(alarm: dict) -> str:
    """A CloudWatch alarm has no severity. Plexus raises an alarm in ALARM
    as a ``warning``, or ``critical`` when its name or description has the
    word "critical" (how many teams name their paging alarms)."""
    words = f"{alarm.get('AlarmName') or ''} {alarm.get('AlarmDescription') or ''}"
    return "critical" if _CRITICAL_RE.search(words) else "warning"


def _dimensions(alarm: dict) -> list[dict]:
    found = [d for d in alarm.get("Dimensions") or [] if isinstance(d, dict)]
    for metric in alarm.get("Metrics") or []:
        stat = (metric or {}).get("MetricStat") or {}
        found += [d for d in ((stat.get("Metric") or {}).get("Dimensions") or []) if isinstance(d, dict)]
    return found


def alarm_events(account_id: int, account_name: str, region: str, response: dict, index: dict[str, dict]) -> list[dict]:
    """The open alert of every alarm in ``ALARM`` in a ``DescribeAlarms``
    answer (its pages merged: ``MetricAlarms`` and ``CompositeAlarms``)."""
    prefix = scope_prefix(PROVIDER, account_id, PART_CLOUDWATCH, region)
    found: list[dict] = []
    alarms = [(a, False) for a in response.get("MetricAlarms") or []]
    alarms += [(a, True) for a in response.get("CompositeAlarms") or []]
    for alarm, composite in alarms:
        if not isinstance(alarm, dict) or alarm.get("StateValue") != "ALARM" or not alarm.get("AlarmName"):
            continue
        name = text(alarm.get("AlarmName"), 255)
        dimensions = _dimensions(alarm)
        entity = None
        for dimension in dimensions:
            entity = resource_entity(index, dimension.get("Value"))
            if entity is not None:
                break
        metric = "/".join(p for p in (text(alarm.get("Namespace"), 120), text(alarm.get("MetricName"), 120)) if p)
        found.append(
            alert_event(
                key=prefix + key_part(name),
                org_ref=0,
                org_name=account_name,
                condition="cloudwatch_alarm",
                title=name,
                message=text(alarm.get("StateReason")),
                severity=alarm_severity(alarm),
                started_at=utc_text(alarm.get("StateTransitionedTimestamp") or alarm.get("StateUpdatedTimestamp")),
                event_type="CloudWatch alarm",
                event_sub_type="Composite alarm" if composite else (metric or "Metric alarm"),
                entity=entity,
                vendor_event_id=text(alarm.get("AlarmArn"), 200),
                detail={
                    "account": account_name,
                    "region": region,
                    "alarm_arn": alarm.get("AlarmArn"),
                    "description": alarm.get("AlarmDescription"),
                    "rule": alarm.get("AlarmRule") if composite else "",
                    "dimensions": [f"{d.get('Name')}={d.get('Value')}" for d in dimensions],
                },
            )
        )
    return found


# ── AWS Health ───────────────────────────────────────────────────────────────


def health_severity(event: dict, *, entity_level: bool = False) -> str:
    """``issue``: ``critical`` for an account-specific issue or one naming
    an affected resource, ``warning`` for a public (service-wide) one;
    ``scheduledChange`` and ``investigation``: ``warning``;
    ``accountNotification``: ``info`` (listed only)."""
    category = str(event.get("eventTypeCategory") or "")
    if category == "issue":
        return "critical" if entity_level or event.get("eventScopeCode") == "ACCOUNT_SPECIFIC" else "warning"
    if category == "accountNotification":
        return "info"
    return "warning"


def health_event_wanted(event: dict, regions: list[str]) -> bool:
    """An open or upcoming event of a region in the account's scope, or of
    no region (a global service)."""
    region = str(event.get("region") or "")
    if str(event.get("statusCode") or "") not in ("open", "upcoming") or not event.get("arn"):
        return False
    return not _REGION_RE.match(region) or region in regions


def health_events(
    account_id: int,
    account_name: str,
    regions: list[str],
    events: list[dict],
    entities: list[dict],
    index: dict[str, dict],
) -> list[dict]:
    """The open alerts of the account's AWS Health events: one per affected
    resource the tracker follows, and one per event for the rest (or for
    an event that names no resource), listing up to
    ``MAX_ENTITIES_PER_EVENT`` of them."""
    prefix = scope_prefix(PROVIDER, account_id, PART_HEALTH)
    by_event: dict[str, list[dict]] = {}
    for entity in entities:
        if isinstance(entity, dict) and str(entity.get("statusCode") or "") in _OPEN_ENTITY_STATES:
            by_event.setdefault(str(entity.get("eventArn") or ""), []).append(entity)
    found: list[dict] = []
    for event in events:
        if not isinstance(event, dict) or not health_event_wanted(event, regions):
            continue
        arn = str(event["arn"])
        category = str(event.get("eventTypeCategory") or "")
        code = text(event.get("eventTypeCode"), 100)
        service = text(event.get("service"), 30)
        upcoming = event.get("statusCode") == "upcoming"
        title = f"AWS Health {'scheduled change' if category == 'scheduledChange' else category}: {code}"
        common: dict[str, Any] = {
            "org_ref": 0,
            "org_name": account_name,
            "condition": f"health_{category or 'event'}",
            "title": title,
            "started_at": utc_text(event.get("startTime")),
            "event_type": "AWS Health",
            "event_sub_type": f"{service} {code}".strip(),
            "vendor_event_id": arn,
        }
        base_detail = {
            "account": account_name,
            "region": event.get("region"),
            "event_arn": arn,
            "status": event.get("statusCode"),
            "scope": event.get("eventScopeCode"),
            "start": utc_text(event.get("startTime")),
            "end": utc_text(event.get("endTime")),
        }
        rest: list[str] = []
        for affected in by_event.get(arn, [])[:MAX_ENTITIES_PER_EVENT]:
            value = text(affected.get("entityValue"), 300)
            tracked = resource_entity(index, value) if value else None
            if tracked is None:
                if value:
                    rest.append(value)
                continue
            found.append(
                alert_event(
                    key=prefix + key_part(f"{arn}|{value}"),
                    message=f"{'Upcoming: ' if upcoming else ''}{service} {code} affects {value}",
                    severity=health_severity(event, entity_level=True),
                    entity=tracked,
                    detail={**base_detail, "entity": value, "entity_status": affected.get("statusCode")},
                    **common,
                )
            )
        total = len(by_event.get(arn, []))
        if rest or not total:
            message = f"{'Upcoming: ' if upcoming else ''}{service} {code}"
            if event.get("region"):
                message += f" in {text(event.get('region'), 30)}"
            if rest:
                message += f"; affects {', '.join(rest[:5])}" + (f" and {total - 5} more" if total > 5 else "")
            found.append(
                alert_event(
                    key=prefix + key_part(arn),
                    message=message,
                    severity=health_severity(event, entity_level=bool(rest)),
                    entity_name=", ".join(rest[:3]),
                    detail={**base_detail, "entities": rest, "entity_count": total},
                    **common,
                )
            )
    return found


# ── EC2 instance status ──────────────────────────────────────────────────────


def _impaired_since(summary: dict) -> str:
    times = [utc_text(d.get("ImpairedSince")) for d in summary.get("Details") or [] if isinstance(d, dict)]
    return min((t for t in times if t), default="")


_CHECKS = (
    ("SystemStatus", "system", "critical", "EC2 system status check failed"),
    ("InstanceStatus", "instance", "critical", "EC2 instance status check failed"),
    ("AttachedEbsStatus", "ebs", "warning", "EC2 attached EBS status check failed"),
)
# Statuses that tell nothing either way: an open alert is left as it is.
_UNDETERMINED = ("initializing", "insufficient-data")


def instance_status_events(
    account_id: int, account_name: str, region: str, statuses: list[dict], index: dict[str, dict], now: str
) -> tuple[list[dict], list[str]]:
    """The open alerts of the impaired status checks and the scheduled
    events (not yet ``[Completed]``) of a region's running instances, and
    the keys whose check is ``initializing`` / ``insufficient-data``
    (undetermined: neither opened nor resolved)."""
    prefix = scope_prefix(PROVIDER, account_id, PART_EC2, region)
    found: list[dict] = []
    unknown: list[str] = []
    for status in statuses:
        instance_id = text((status or {}).get("InstanceId"), 64)
        if not instance_id:
            continue
        entity = resource_entity(index, instance_id)
        name = text((entity or {}).get("name") or instance_id, 200)
        for field_name, check, severity, title in _CHECKS:
            summary = status.get(field_name) or {}
            value = str(summary.get("Status") or "").lower() if isinstance(summary, dict) else ""
            key = f"{prefix}{instance_id}:{check}"
            if value in _UNDETERMINED:
                unknown.append(key)
            if value != "impaired":
                continue
            found.append(
                alert_event(
                    key=key,
                    org_ref=0,
                    org_name=account_name,
                    condition=f"ec2_{check}_impaired",
                    title=title,
                    message=f"{title} on {name} ({region})",
                    severity=severity,
                    started_at=_impaired_since(summary) or now,
                    event_type="EC2 status check",
                    event_sub_type=field_name,
                    entity=entity,
                    entity_name=instance_id,
                    vendor_event_id=instance_id,
                    detail={"account": account_name, "region": region, "instance": instance_id, "check": field_name},
                    # An impaired instance is an availability problem of the
                    # entity: not notified twice with the tracker.
                    tracker_scope="entity",
                )
            )
        for scheduled in status.get("Events") or []:
            if not isinstance(scheduled, dict):
                continue
            description = text(scheduled.get("Description"), 300)
            if description.lower().startswith(_DONE_PREFIXES):
                continue
            code = text(scheduled.get("Code"), 40)
            event_id = text(scheduled.get("InstanceEventId"), 64) or code
            not_before = utc_text(scheduled.get("NotBefore"))
            found.append(
                alert_event(
                    key=f"{prefix}{instance_id}:event:{key_part(event_id)}",
                    org_ref=0,
                    org_name=account_name,
                    condition="ec2_scheduled_event",
                    title=f"EC2 scheduled event: {code}",
                    message=f"{description or code} on {name}"
                    + (f", not before {not_before} UTC" if not_before else ""),
                    severity="warning",
                    started_at=now,
                    event_type="EC2 scheduled event",
                    event_sub_type=code,
                    entity=entity,
                    entity_name=instance_id,
                    vendor_event_id=event_id,
                    detail={
                        "account": account_name,
                        "region": region,
                        "instance": instance_id,
                        "not_before": not_before,
                        "not_after": utc_text(scheduled.get("NotAfter")),
                    },
                )
            )
    return found, unknown
