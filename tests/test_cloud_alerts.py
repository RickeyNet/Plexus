"""AWS and Azure alert feeds: the normalisation (``netcontrol.integrations.
aws.alerts``, ``netcontrol.integrations.azure.alerts``, shared helpers in
``netcontrol.integrations.cloud_alerts``), the current-state additions of
the shared pipeline (``netcontrol.routes.vendor_alerts``: complete scopes,
undetermined keys, notes, parts, per-provider defaults) and the two
providers (``netcontrol.routes.aws_alerts``, ``netcontrol.routes.azure_alerts``).

Built from the invented answers in ``aws.sample`` and ``azure.sample``;
boto3, azure-identity and the network are replaced by fakes, so the tests
run without the cloud SDKs.
"""

from __future__ import annotations

import httpx
import netcontrol.routes.aws_alerts as aws_routes
import netcontrol.routes.azure_alerts as azure_routes
import netcontrol.routes.topology_availability as tracking
import netcontrol.routes.vendor_alerts as feeds
import pytest
import routes.database as db_module
from netcontrol.integrations import cloud_alerts
from netcontrol.integrations.aws import alerts as aws, sample as aws_sample
from netcontrol.integrations.azure import alerts as azure, sample as azure_sample
from netcontrol.routes.meraki_topology import AWS_ORG_REF, AZURE_ORG_REF

from test_meraki_topology import _CsrfClient, api  # noqa: F401 - the fixture is used by name

R1, R2 = "us-east-1", "us-west-2"
INSTANCE = aws_sample.ALERT_INSTANCE
NOW = "2026-11-20 09:00:00"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.setattr(feeds, "_CONFIG", {})
    monkeypatch.setattr(feeds, "_LAST_CYCLE", {})


@pytest.fixture
def notifications(monkeypatch):
    events: list[dict] = []

    async def _capture(event: dict) -> None:
        events.append(event)

    monkeypatch.setattr(tracking.notification_channels, "on_alert_created", _capture)
    return events


def _tracked(*entities: tuple[str, str, str]) -> dict[str, dict]:
    return cloud_alerts.entity_index(
        [{"entity_type": t, "entity_id": i, "name": n, "site": "vpc-0example"} for t, i, n in entities]
    )


# ── Shared helpers ───────────────────────────────────────────────────────────


def test_times_keys_and_detail_are_bounded():
    assert cloud_alerts.utc_text("2026-11-20T09:00:00.1234567+01:00") == "2026-11-20 08:00:00"
    assert cloud_alerts.utc_text("2026-11-20T08:00:00Z") == "2026-11-20 08:00:00"
    assert cloud_alerts.utc_text("") == "" and cloud_alerts.utc_text("soon") == ""
    assert cloud_alerts.scope_prefix("aws", 7, "cloudwatch", R1) == "aws:7:cloudwatch:us-east-1:"
    long_id = "x" * 400
    assert cloud_alerts.key_part("short") == "short"
    assert cloud_alerts.key_part(long_id).startswith("h:") and len(cloud_alerts.key_part(long_id)) == 42
    detail = cloud_alerts.bounded_detail({"a": "y" * 1000, "b": "", "c": list(range(50)), "d": 3})
    assert len(detail["a"]) == cloud_alerts.MAX_DETAIL_VALUE and "b" not in detail
    assert len(detail["c"]) == cloud_alerts.MAX_DETAIL_ITEMS and detail["d"] == 3


def test_absent_keys_only_within_complete_scopes():
    stored = ["aws:1:cloudwatch:us-east-1:a", "aws:1:cloudwatch:us-east-1:b", "aws:1:cloudwatch:us-west-2:c"]
    assert feeds.absent_keys(stored, ["aws:1:cloudwatch:us-east-1:"], {"aws:1:cloudwatch:us-east-1:a"}) == [
        "aws:1:cloudwatch:us-east-1:b"
    ]
    assert feeds.absent_keys(stored, [], set()) == [] and feeds.absent_keys(stored, [""], set()) == []


# ── AWS normalisation ────────────────────────────────────────────────────────


def test_cloudwatch_alarms_map_to_alerts_with_their_entity():
    index = _tracked(("device", f"i:{INSTANCE}", "web-01"))
    answer = aws_sample.describe_alarms(
        [
            aws_sample.metric_alarm(),
            aws_sample.metric_alarm("db-latency", state="OK"),
            aws_sample.metric_alarm("Disk CRITICAL", instance=aws_sample.ALERT_OTHER_INSTANCE, description=""),
        ],
        [aws_sample.composite_alarm()],
    )
    cpu, disk, composite = aws.alarm_events(4, "Example AWS", R1, answer, index)
    assert cpu["key"] == "aws:4:cloudwatch:us-east-1:web-cpu-high" and cpu["state"] == "open"
    assert cpu["severity"] == "warning" and cpu["entity_type"] == "device" and cpu["entity_id"] == f"i:{INSTANCE}"
    assert cpu["entity_name"] == "web-01" and cpu["site"] == "vpc-0example" and cpu["tracker_scope"] == ""
    assert cpu["started_at"] == "2026-11-20 08:00:00" and "Threshold Crossed" in cpu["message"]
    assert cpu["event_sub_type"] == "AWS/EC2/CPUUtilization"
    assert cpu["detail"]["dimensions"] == [f"InstanceId={INSTANCE}"] and cpu["detail"]["region"] == R1
    # The word "critical" makes it critical; an untracked instance is account-level.
    assert disk["severity"] == "critical" and disk["entity_id"] == ""
    assert composite["event_sub_type"] == "Composite alarm" and composite["severity"] == "critical"
    assert composite["detail"]["rule"].startswith("ALARM(")


def test_a_managed_service_is_matched_by_its_resource_uid():
    index = _tracked(("service", "aws:rds_instance:orders-db", "orders-db"))
    found = aws.resource_entity(index, "arn:aws:rds:us-east-1:123456789012:db:orders-db")
    assert found and found["entity_id"] == "aws:rds_instance:orders-db"
    assert aws.resource_entity(index, "nothing-here") is None


def test_health_events_per_tracked_entity_and_per_event():
    index = _tracked(("device", f"i:{INSTANCE}", "web-01"))
    retire = aws_sample.health_event()
    outage = aws_sample.health_event("AWS_EC2_OPERATIONAL_ISSUE", category="issue", status="open", scope="PUBLIC")
    elsewhere = aws_sample.health_event(
        "AWS_EC2_OPERATIONAL_ISSUE", category="issue", status="open", region="eu-west-1"
    )
    entities = [
        aws_sample.health_entity(retire),
        aws_sample.health_entity(retire, aws_sample.ALERT_OTHER_INSTANCE),
        aws_sample.health_entity(retire, "i-0resolved000000000", status="RESOLVED"),
    ]
    found = aws.health_events(4, "Example AWS", [R1, R2], [retire, outage, elsewhere], entities, index)
    tracked, rest, public = found
    assert tracked["entity_id"] == f"i:{INSTANCE}" and tracked["severity"] == "warning"
    assert tracked["key"].startswith("aws:4:health:") and tracked["title"].startswith("AWS Health scheduled change")
    assert "Upcoming" in tracked["message"]
    assert rest["entity_id"] == "" and rest["detail"]["entities"] == [aws_sample.ALERT_OTHER_INSTANCE]
    assert rest["detail"]["entity_count"] == 2
    # A public issue of a region in scope: a warning; a region out of scope is left out.
    assert public["severity"] == "warning" and public["condition"] == "health_issue"
    assert aws.health_severity({"eventTypeCategory": "issue", "eventScopeCode": "ACCOUNT_SPECIFIC"}) == "critical"
    assert aws.health_severity({"eventTypeCategory": "accountNotification"}) == "info"


def test_ec2_status_checks_and_scheduled_events():
    index = _tracked(("device", f"i:{INSTANCE}", "web-01"))
    statuses = [
        aws_sample.instance_status(system="impaired", events=[aws_sample.scheduled_event()]),
        aws_sample.instance_status(
            aws_sample.ALERT_OTHER_INSTANCE,
            status="insufficient-data",
            ebs="impaired",
            events=[aws_sample.scheduled_event(done=True)],
        ),
    ]
    found, unknown = aws.instance_status_events(4, "Example AWS", R1, statuses, index, NOW)
    system, reboot, ebs = found
    assert system["key"] == f"aws:4:ec2_status:us-east-1:{INSTANCE}:system" and system["severity"] == "critical"
    assert system["tracker_scope"] == "entity" and system["entity_id"] == f"i:{INSTANCE}"
    assert system["started_at"] == "2026-11-20 08:00:00"
    assert reboot["condition"] == "ec2_scheduled_event" and reboot["severity"] == "warning"
    assert "not before 2026-11-25 02:00:00" in reboot["message"]
    assert ebs["severity"] == "warning" and ebs["entity_id"] == "" and ebs["tracker_scope"] == ""
    assert unknown == [f"aws:4:ec2_status:us-east-1:{aws_sample.ALERT_OTHER_INSTANCE}:instance"]


# ── Azure normalisation ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        ("Sev0", "critical"),
        ("Sev1", "critical"),
        ("Sev2", "warning"),
        ("Sev3", "info"),
        ("Sev4", "info"),
        ("", "warning"),
    ],
)
def test_azure_severity_mapping(severity, expected):
    (event,) = azure.monitor_alert_events(
        9, "Example Azure", "sub", [azure_sample.monitor_alert(severity=severity)], {}
    )
    assert event["severity"] == expected


def test_azure_monitor_alerts_and_resource_health():
    sub = azure_sample.ALERT_SUBSCRIPTION
    index = _tracked(
        ("device", f"vm:{sub}:rg-app:app-vm-01", "app-vm-01"),
        ("device", f"vng:{sub}:rg-hub:hub-vpn-gw", "hub-vpn-gw"),
    )
    alerts = [
        azure_sample.monitor_alert(),
        azure_sample.monitor_alert("2", condition="Resolved"),
        azure_sample.monitor_alert("3", state="Closed"),
    ]
    (fired,) = azure.monitor_alert_events(9, "Example Azure", sub, alerts, index)
    assert fired["key"] == "azure:9:monitor_alerts:11111111-0000-0000-0000-000000000001"
    assert fired["entity_id"] == f"vm:{sub}:rg-app:app-vm-01" and fired["title"] == "app-vm-cpu"
    assert fired["started_at"] == "2026-11-20 08:00:00" and fired["event_sub_type"] == "Platform Sev1"
    statuses = [
        azure_sample.availability_status(),
        azure_sample.availability_status(azure_sample.ALERT_GATEWAY_ID, "Degraded"),
        azure_sample.availability_status(azure_sample.ALERT_VM_ID.replace("01", "02"), "Unknown"),
        azure_sample.availability_status(azure_sample.ALERT_VM_ID.replace("01", "03"), "Available"),
    ]
    found, unknown = azure.resource_health_events(9, "Example Azure", sub, statuses, index, NOW)
    down, degraded = found
    assert down["severity"] == "critical" and down["tracker_scope"] == "entity" and down["entity_name"] == "app-vm-01"
    assert down["condition"] == "resource_health_unavailable" and "host failure" in down["message"]
    assert degraded["severity"] == "warning" and degraded["entity_id"] == f"vng:{sub}:rg-hub:hub-vpn-gw"
    assert len(unknown) == 1 and unknown[0].startswith("azure:9:resource_health:")
    # A resource ID is matched whatever its case.
    assert azure.candidates(azure_sample.ALERT_VM_ID.upper())[0].lower() == f"azure:vm:{sub}:rg-app:app-vm-01"


# ── AWS provider ─────────────────────────────────────────────────────────────


class _FakeClient:
    def __init__(self, service: str, region: str, answers: dict, calls: list) -> None:
        self.service, self.region, self.answers, self.calls = service, region, answers, calls

    def __getattr__(self, operation: str):
        def call(**kwargs):
            self.calls.append((self.service, self.region, operation))
            answer = self.answers.get((self.service, self.region, operation), {})
            if isinstance(answer, list):
                answer = answer.pop(0) if answer else {}
            if isinstance(answer, Exception):
                raise answer
            return answer

        return call


class _FakeSession:
    def __init__(self, answers: dict, calls: list) -> None:
        self.answers, self.calls = answers, calls

    def client(self, service: str, region: str):
        return _FakeClient(service, region, self.answers, self.calls)


class _ClientError(Exception):
    """botocore's ClientError shape (``response["Error"]``)."""

    def __init__(self, code: str, message: str = "refused") -> None:
        super().__init__(message)
        self.response = {"Error": {"Code": code, "Message": message}}


def _aws(monkeypatch, answers: dict, regions=(R1, R2)) -> list:
    calls: list = []
    monkeypatch.setattr(aws_routes, "_require_sdk", lambda: None)
    monkeypatch.setattr(aws_routes, "_session", lambda auth: _FakeSession(answers, calls))
    monkeypatch.setattr(aws_routes, "_regions", lambda account, session: list(regions))
    monkeypatch.setattr(aws_routes, "_client", lambda session, service, region: session.client(service, region))
    return calls


async def _aws_account(name: str = "Example AWS") -> dict:
    account = await db_module.create_cloud_account(
        "aws",
        name,
        account_identifier=aws_sample.ALERT_ACCOUNT,
        region_scope=f"{R1},{R2}",
        auth_config_json={"access_key_id": "AKIDEXAMPLE", "secret_access_key": "example-secret"},
    )
    assert account
    return account


async def _feed_row(provider: str, account_id: int) -> dict:
    rows = await db_module.list_vendor_alert_feeds(provider, "current_state")
    (row,) = [r for r in rows if r["org_ref"] == account_id]
    return row


async def _open(provider: str) -> dict[str, dict]:
    return {r["alert_key"]: r for r in await db_module.list_vendor_alerts(provider=provider)}


async def test_a_complete_region_resolves_what_it_no_longer_reports(monkeypatch, notifications):
    account = await _aws_account()
    cw1, cw2 = ("cloudwatch", R1, "describe_alarms"), ("cloudwatch", R2, "describe_alarms")
    answers: dict = {
        cw1: [aws_sample.describe_alarms([aws_sample.metric_alarm()])],
        cw2: [aws_sample.describe_alarms([aws_sample.metric_alarm("api-errors", region=R2)])],
        ("ec2", R1, "describe_instance_status"): {"InstanceStatuses": []},
        ("ec2", R2, "describe_instance_status"): {"InstanceStatuses": []},
        ("health", R1, "describe_events"): {"events": []},
    }
    _aws(monkeypatch, answers)
    first = await feeds.run_poll_cycle("aws")
    assert first["polled"] == 1 and first["failed"] == 0 and first["new"] == 2 and first["alerted"] == 2
    stored = await _open("aws")
    assert set(stored) == {
        f"aws:{account['id']}:cloudwatch:{R1}:web-cpu-high",
        f"aws:{account['id']}:cloudwatch:{R2}:api-errors",
    }
    assert {r["org_ref"] for r in stored.values()} == {AWS_ORG_REF}
    assert {r["org_name"] for r in stored.values()} == {"Example AWS"}
    assert len(notifications) == 2 and "Example AWS" in notifications[0]["message"]
    row = await _feed_row("aws", account["id"])
    assert row["feed_status"] == "ok" and row["last_error"] == ""

    # Next poll: us-east-1 read in full without the alarm, us-west-2 failed.
    answers[cw1] = [aws_sample.describe_alarms([])]
    answers[cw2] = [_ClientError("Throttling", "Rate exceeded")]
    second = await feeds.run_poll_cycle("aws", force=True)
    assert second["failed"] == 0 and second["resolved"] == 1
    assert set(await _open("aws")) == {f"aws:{account['id']}:cloudwatch:{R2}:api-errors"}
    row = await _feed_row("aws", account["id"])
    # Partial: shown, not backed off.
    assert row["feed_status"] == "partial" and "CloudWatch alarms in us-west-2" in row["last_error"]
    assert row["failures"] == 0 and row["next_poll_at"] == ""
    resolved = [n for n in notifications if n.get("alert_type") == "vendor_alert"]
    assert len(resolved) == 2


async def test_a_failed_read_resolves_nothing_and_backs_off(monkeypatch, notifications):
    account = await _aws_account()
    answers: dict = {("cloudwatch", R1, "describe_alarms"): [aws_sample.describe_alarms([aws_sample.metric_alarm()])]}
    _aws(monkeypatch, answers, regions=(R1,))
    feeds._CONFIG["aws"] = feeds.sanitize_config({"disabled_parts": ["health", "ec2_status"]}, aws_routes.PROVIDER)
    await feeds.run_poll_cycle("aws")
    assert len(await _open("aws")) == 1
    answers[("cloudwatch", R1, "describe_alarms")] = [_ClientError("AccessDeniedException", "not authorized")]
    result = await feeds.run_poll_cycle("aws", force=True)
    assert result["failed"] == 1 and result["sources"][0]["feed_status"] == "no_access"
    assert len(await _open("aws")) == 1
    row = await _feed_row("aws", account["id"])
    assert row["failures"] == 1 and row["next_poll_at"] > row["last_poll_at"] and "not authorized" in row["last_error"]


async def test_a_page_bound_reads_in_part_and_resolves_nothing(monkeypatch):
    await _aws_account()
    pages = [aws_sample.describe_alarms([aws_sample.metric_alarm()], token="t1")]
    pages += [aws_sample.describe_alarms([], token=f"t{n}") for n in range(2, 20)]
    answers: dict = {("cloudwatch", R1, "describe_alarms"): pages}
    _aws(monkeypatch, answers, regions=(R1,))
    feeds._CONFIG["aws"] = feeds.sanitize_config({"disabled_parts": ["health", "ec2_status"]}, aws_routes.PROVIDER)
    await feeds.run_poll_cycle("aws")
    assert len(await _open("aws")) == 1
    # Ten pages and still a token: read in part, the stored alert is kept.
    answers[("cloudwatch", R1, "describe_alarms")] = [aws_sample.describe_alarms([], token="more")] * 12
    result = await feeds.run_poll_cycle("aws", force=True)
    assert result["resolved"] == 0 and len(await _open("aws")) == 1
    assert "read in part" in result["sources"][0]["note"]


async def test_health_without_a_support_plan_is_a_status_not_a_failure(monkeypatch):
    account = await _aws_account()
    answers: dict = {
        ("cloudwatch", R1, "describe_alarms"): aws_sample.describe_alarms([aws_sample.metric_alarm()]),
        ("health", R1, "describe_events"): _ClientError(aws.HEALTH_PLAN_CODE, "The AWS account is not subscribed"),
    }
    calls = _aws(monkeypatch, answers, regions=(R1,))
    feeds._CONFIG["aws"] = feeds.sanitize_config({"disabled_parts": ["ec2_status"]}, aws_routes.PROVIDER)
    result = await feeds.run_poll_cycle("aws")
    assert result["failed"] == 0 and result["new"] == 1
    row = await _feed_row("aws", account["id"])
    assert row["feed_status"] == "partial" and row["last_error"] == aws.HEALTH_PLAN_NOTE and row["failures"] == 0
    assert "health_refused_until" in row["feed_cursor"]
    # The next poll does not ask Health again; CloudWatch is still read.
    await feeds.run_poll_cycle("aws", force=True)
    assert [c for c in calls if c[0] == "health"] == [("health", R1, "describe_events")]
    assert [c for c in calls if c[0] == "cloudwatch"] == [("cloudwatch", R1, "describe_alarms")] * 2
    assert (await _feed_row("aws", account["id"]))["last_error"] == aws.HEALTH_PLAN_NOTE


async def test_health_events_name_their_affected_entities(monkeypatch):
    await _aws_account()
    event = aws_sample.health_event()
    answers: dict = {
        ("health", R1, "describe_events"): {"events": [event]},
        ("health", R1, "describe_affected_entities"): {"entities": [aws_sample.health_entity(event)]},
    }
    calls = _aws(monkeypatch, answers, regions=(R1,))
    feeds._CONFIG["aws"] = feeds.sanitize_config({"disabled_parts": ["cloudwatch", "ec2_status"]}, aws_routes.PROVIDER)
    assert (await feeds.run_poll_cycle("aws"))["new"] == 1
    (row,) = (await _open("aws")).values()
    assert row["event_type"] == "AWS Health" and row["detail"]["entities"] == [INSTANCE]
    assert ("health", R1, "describe_affected_entities") in calls


async def test_a_missing_sdk_is_a_feed_status(monkeypatch):
    account = await _aws_account()

    def _missing():
        raise aws_routes.CloudCollectorUnavailable("The AWS alert feed requires boto3")

    monkeypatch.setattr(aws_routes, "_require_sdk", _missing)
    result = await feeds.run_poll_cycle("aws")
    assert result["failed"] == 1
    row = await _feed_row("aws", account["id"])
    assert "boto3 is not installed" in row["last_error"] and row["feed_status"] == "error"
    # An access-type problem: backed off for up to an hour.
    assert row["next_poll_at"] > row["last_poll_at"]


async def test_aws_errors_are_described():
    describe = aws_routes.describe_error
    assert describe(_ClientError("UnauthorizedOperation")).access
    limited = describe(_ClientError("ThrottlingException"))
    assert limited.feed_status == "rate_limited" and not limited.access
    assert describe(_ClientError("InternalError")).feed_status == "error"


async def test_an_alarm_on_a_tracked_instance_is_muted_with_it(monkeypatch, notifications):
    await _aws_account()
    snapshot = {
        "nodes": [
            {"id": f"i:{INSTANCE}", "kind": "server", "label": "web-01", "site": "vpc-0example", "status": "online"}
        ],
        "edges": [],
        "sites": [{"id": "vpc-0example", "name": "Production VPC"}],
    }
    await tracking.record_snapshot_states("aws", AWS_ORG_REF, snapshot, now=NOW)
    await db_module.create_topology_mute(
        "aws",
        AWS_ORG_REF,
        "entity",
        entity_type="device",
        entity_id=f"i:{INSTANCE}",
        reason="rebuild",
        created_by="admin",
    )
    answers: dict = {("cloudwatch", R1, "describe_alarms"): aws_sample.describe_alarms([aws_sample.metric_alarm()])}
    _aws(monkeypatch, answers, regions=(R1,))
    feeds._CONFIG["aws"] = feeds.sanitize_config({"disabled_parts": ["health", "ec2_status"]}, aws_routes.PROVIDER)
    await feeds.run_poll_cycle("aws")
    (row,) = (await _open("aws")).values()
    assert row["entity_type"] == "device" and row["entity_id"] == f"i:{INSTANCE}" and row["site"] == "Production VPC"
    assert row["alert_via"] == "muted" and notifications == []


async def test_a_part_switched_off_resolves_its_alerts(monkeypatch):
    await _aws_account()
    answers: dict = {("cloudwatch", R1, "describe_alarms"): aws_sample.describe_alarms([aws_sample.metric_alarm()])}
    calls = _aws(monkeypatch, answers, regions=(R1,))
    feeds._CONFIG["aws"] = feeds.sanitize_config({"disabled_parts": ["health", "ec2_status"]}, aws_routes.PROVIDER)
    await feeds.run_poll_cycle("aws")
    assert len(await _open("aws")) == 1
    feeds._CONFIG["aws"] = feeds.sanitize_config(
        {"disabled_parts": ["health", "ec2_status", "cloudwatch"]}, aws_routes.PROVIDER
    )
    result = await feeds.run_poll_cycle("aws", force=True)
    assert result["resolved"] == 1 and await _open("aws") == {}
    assert len([c for c in calls if c[0] == "cloudwatch"]) == 1
    # Switched on again: the alarm never left ALARM (its start is older than
    # the resolve), and it is open again because it is read as open now.
    feeds._CONFIG["aws"] = feeds.sanitize_config({"disabled_parts": ["health", "ec2_status"]}, aws_routes.PROVIDER)
    again = await feeds.run_poll_cycle("aws", force=True)
    assert again["alerted"] == 1 and len(await _open("aws")) == 1


async def test_a_region_out_of_scope_and_an_account_no_longer_polled_resolve(monkeypatch):
    account = await _aws_account()
    answers: dict = {
        ("cloudwatch", R1, "describe_alarms"): aws_sample.describe_alarms([aws_sample.metric_alarm()]),
        ("cloudwatch", R2, "describe_alarms"): aws_sample.describe_alarms(
            [aws_sample.metric_alarm("api-errors", region=R2)]
        ),
    }
    feeds._CONFIG["aws"] = feeds.sanitize_config({"disabled_parts": ["health", "ec2_status"]}, aws_routes.PROVIDER)
    _aws(monkeypatch, answers)
    await feeds.run_poll_cycle("aws")
    assert len(await _open("aws")) == 2
    # us-west-2 leaves the account's region scope: nothing reads it any more.
    _aws(monkeypatch, answers, regions=(R1,))
    result = await feeds.run_poll_cycle("aws", force=True)
    assert result["resolved"] == 1
    assert set(await _open("aws")) == {f"aws:{account['id']}:cloudwatch:{R1}:web-cpu-high"}
    # The account is disabled: its alerts would stay open for ever.
    await db_module.update_cloud_account(account["id"], enabled=False)
    result = await feeds.run_poll_cycle("aws", force=True)
    assert result["polled"] == 0 and result["resolved"] == 1 and await _open("aws") == {}


def test_orphaned_keys_only_of_sources_no_longer_polled():
    stored = ["aws:7:cloudwatch:us-east-1:a", "aws:8:health:b", "aws:x:c", "cato:7:d", "odd"]
    assert feeds.orphaned_keys("aws", stored, {7}) == ["aws:8:health:b"]
    assert feeds.orphaned_keys("aws", stored, set()) == ["aws:7:cloudwatch:us-east-1:a", "aws:8:health:b"]


# ── Azure provider ───────────────────────────────────────────────────────────


async def _azure_account() -> dict:
    account = await db_module.create_cloud_account(
        "azure",
        "Example Azure",
        account_identifier=azure_sample.ALERT_SUBSCRIPTION,
        auth_config_json={"subscription_id": azure_sample.ALERT_SUBSCRIPTION},
    )
    assert account
    return account


def _azure(monkeypatch, answers: dict) -> list[str]:
    calls: list[str] = []

    async def send(method: str, url: str, **kwargs) -> httpx.Response:
        assert method == "GET" and kwargs["headers"]["Authorization"] == "Bearer token-example"
        calls.append(url)
        part = "alertsmanagement" if "AlertsManagement" in url else "resourcehealth"
        answer = answers[part]
        answer = answer.pop(0) if isinstance(answer, list) else answer
        return answer if isinstance(answer, httpx.Response) else httpx.Response(200, json=answer)

    monkeypatch.setattr(azure_routes, "_SEND", send)
    monkeypatch.setattr(azure_routes, "_token", lambda auth: "token-example")
    return calls


async def test_azure_poll_resolves_per_part_and_keeps_unknown(monkeypatch, notifications):
    account = await _azure_account()
    answers: dict = {
        "alertsmanagement": azure_sample.arm_page([azure_sample.monitor_alert()]),
        "resourcehealth": azure_sample.arm_page([azure_sample.availability_status()]),
    }
    calls = _azure(monkeypatch, answers)
    first = await feeds.run_poll_cycle("azure")
    assert first["failed"] == 0 and first["new"] == 2
    assert all(url.startswith("https://management.azure.com/subscriptions/") for url in calls)
    assert "api-version=2019-03-01" in calls[0] and "monitorCondition=Fired" in calls[0]
    assert "api-version=2025-05-01" in calls[1]
    stored = await _open("azure")
    assert {r["org_ref"] for r in stored.values()} == {AZURE_ORG_REF}

    # The alert resolved; the VM's health is Unknown (left open); a 403 on
    # nothing else.
    answers["alertsmanagement"] = azure_sample.arm_page([azure_sample.monitor_alert(condition="Resolved")])
    answers["resourcehealth"] = azure_sample.arm_page([azure_sample.availability_status(state="Unknown")])
    second = await feeds.run_poll_cycle("azure", force=True)
    assert second["resolved"] == 1
    (left,) = (await _open("azure")).values()
    assert left["condition"] == "resource_health_unavailable"
    answers["resourcehealth"] = azure_sample.arm_page([azure_sample.availability_status(state="Available")])
    assert (await feeds.run_poll_cycle("azure", force=True))["resolved"] == 1
    assert await _open("azure") == {}
    assert (await _feed_row("azure", account["id"]))["feed_status"] == "ok"


async def test_azure_one_part_refused_and_a_foreign_next_link(monkeypatch):
    account = await _azure_account()
    answers: dict = {
        "alertsmanagement": azure_sample.arm_page([azure_sample.monitor_alert()]),
        "resourcehealth": azure_sample.arm_page([azure_sample.availability_status()]),
    }
    calls = _azure(monkeypatch, answers)
    await feeds.run_poll_cycle("azure")
    answers["alertsmanagement"] = httpx.Response(
        403, json={"error": {"code": "AuthorizationFailed", "message": "no read access"}}
    )
    answers["resourcehealth"] = azure_sample.arm_page([], next_link="https://elsewhere.example.com/next")
    result = await feeds.run_poll_cycle("azure", force=True)
    # Neither part was read in full: nothing resolved, nothing sent elsewhere.
    assert result["failed"] == 0 and result["resolved"] == 0 and len(await _open("azure")) == 2
    assert not [url for url in calls if httpx.URL(url).host == "elsewhere.example.com"]
    row = await _feed_row("azure", account["id"])
    assert row["feed_status"] == "partial" and "AuthorizationFailed" in row["last_error"]
    assert "Resource Health: read in part" in row["last_error"]


async def test_azure_errors_and_missing_identity(monkeypatch):
    account = await _azure_account()

    def _missing(auth):
        raise azure_routes.CloudCollectorUnavailable("no azure-identity")

    monkeypatch.setattr(azure_routes, "_token", _missing)
    await feeds.run_poll_cycle("azure")
    row = await _feed_row("azure", account["id"])
    assert "azure-identity is not installed" in row["last_error"]
    describe = azure_routes.describe_error
    assert describe(azure_routes.ArmError(429)).feed_status == "rate_limited"
    assert describe(azure_routes.ArmError(None)).feed_status == "unreachable"
    assert describe(azure_routes.ArmError(401, "InvalidAuthenticationToken")).access


# ── Settings and API ─────────────────────────────────────────────────────────


def test_cloud_feed_settings_parts_and_defaults(api):  # noqa: F811
    resp = api.get("/api/monitoring/vendor-alerts/aws/settings")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["config"]["interval_seconds"] == 300 and body["config"]["disabled_parts"] == []
    assert body["current_state"] is True
    assert [p["key"] for p in body["parts"]] == ["cloudwatch", "health", "ec2_status"]
    changed = api.put(
        "/api/monitoring/vendor-alerts/aws/settings", json={"disabled_parts": ["health", "bogus", "health"]}
    )
    assert changed.status_code == 200, changed.text
    assert changed.json()["config"]["disabled_parts"] == ["health"]
    assert [p["enabled"] for p in changed.json()["parts"]] == [True, False, True]
    azure_body = api.get("/api/monitoring/vendor-alerts/azure/settings").json()
    assert [p["key"] for p in azure_body["parts"]] == ["monitor_alerts", "resource_health"]
    # The Cato feed keeps its settings shape (no parts).
    cato = api.get("/api/monitoring/vendor-alerts/cato/settings").json()
    assert "disabled_parts" not in cato["config"] and cato["parts"] == [] and cato["current_state"] is False
    api._c.cookies.clear()
    assert api.get("/api/monitoring/vendor-alerts/aws/settings").status_code == 401
    assert api.post("/api/monitoring/vendor-alerts/azure/poll").status_code == 401


async def test_sample_accounts_are_not_polled():
    await db_module.create_cloud_account("aws", "Sample AWS", auth_type="sample")
    real = await _aws_account("Example AWS 2")
    sources = await aws_routes.PROVIDER.list_sources()
    assert [s["id"] for s in sources] == [real["id"]] and "auth_config_json" not in sources[0]
