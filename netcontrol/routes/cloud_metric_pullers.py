"""
cloud_metric_pullers.py -- Scheduled traffic-metric pullers for each cloud provider.

Pulls traffic metrics from:
  - AWS: CloudWatch Metrics
  - Azure: Azure Monitor Metrics
  - GCP: Cloud Monitoring

Records are normalized and fed into the existing traffic-metric ingest pipeline
(``create_cloud_traffic_metrics_batch`` -> ``cloud_traffic_metrics`` table).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import routes.database as db

from netcontrol.routes.cloud_visibility import (
    _build_traffic_metric_rows_for_ingest,
    _normalize_aws_traffic_metric_records,
    _normalize_azure_traffic_metric_records,
    _normalize_gcp_traffic_metric_records,
)
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.cloud_metric_pullers")

_DEFAULT_LOOKBACK_MINUTES = 15
_MAX_RECORDS_PER_PULL = 10_000


async def _get_cursor(account_id: int) -> dict:
    row = await db.get_cloud_traffic_metric_sync_cursor(account_id)
    return row or {}


async def _set_cursor(account_id: int, *, last_pull_end: str, extra: dict | None = None) -> None:
    await db.upsert_cloud_traffic_metric_sync_cursor(
        account_id,
        last_pull_end=last_pull_end,
        extra_json=extra,
    )


def _window(cursor: dict, lookback_minutes: int = _DEFAULT_LOOKBACK_MINUTES) -> tuple[datetime, datetime]:
    """Return (start, end) datetimes for the next pull window."""
    now = datetime.now(UTC)
    end = now
    last_pull = cursor.get("last_pull_end")
    if last_pull:
        try:
            start = datetime.fromisoformat(str(last_pull).replace("Z", "+00:00"))
            if start.tzinfo is None:
                start = start.replace(tzinfo=UTC)
        except Exception:
            start = now - timedelta(minutes=lookback_minutes)
    else:
        start = now - timedelta(minutes=lookback_minutes)

    floor = now - timedelta(hours=24)
    if start < floor:
        start = floor
    return start, end


async def pull_aws_traffic_metrics(account: dict, *, lookback_minutes: int = _DEFAULT_LOOKBACK_MINUTES) -> dict:
    """Pull network traffic metrics from AWS CloudWatch."""
    account_id = int(account["id"])
    auth = _parse_auth_config(account)
    resource_ids = _parse_list(auth.get("resource_ids"))
    metric_names = _parse_list(auth.get("metric_names")) or [
        "NetworkIn",
        "NetworkOut",
        "NetworkPacketsIn",
        "NetworkPacketsOut",
    ]
    namespace = str(auth.get("metric_namespace") or "AWS/EC2").strip() or "AWS/EC2"
    resource_dimension_name = str(auth.get("resource_dimension_name") or "InstanceId").strip() or "InstanceId"

    if not resource_ids:
        return {"ok": False, "error": "missing_resource_ids", "ingested": 0}

    try:
        import boto3  # noqa: F401
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        return {"ok": False, "error": "boto3_not_installed", "ingested": 0}

    session = _build_boto3_session(auth)
    regions = _parse_regions(account)
    cursor = await _get_cursor(account_id)
    start_dt, end_dt = _window(cursor, lookback_minutes=lookback_minutes)

    period = max(60, min(3600, int(auth.get("period_seconds") or 300)))
    total_ingested = 0
    errors: list[str] = []

    for region in regions:
        try:
            client = session.client("cloudwatch", region_name=region)
            records = await _aws_cloudwatch_fetch(
                client,
                namespace=namespace,
                metric_names=metric_names,
                resource_dimension_name=resource_dimension_name,
                resource_ids=resource_ids,
                start=start_dt,
                end=end_dt,
                period_seconds=period,
            )
            if not records:
                continue
            normalized = _normalize_aws_traffic_metric_records(records[:_MAX_RECORDS_PER_PULL])
            if not normalized:
                continue
            rows = _build_traffic_metric_rows_for_ingest(
                account_id,
                "aws",
                normalized,
                source="scheduled_pull",
            )
            total_ingested += await db.create_cloud_traffic_metrics_batch(rows)
        except (BotoCoreError, ClientError) as exc:
            msg = f"AWS traffic pull failed region={region}: {type(exc).__name__}"
            LOGGER.warning(msg)
            errors.append(msg)
        except Exception as exc:
            msg = f"AWS traffic pull unexpected error region={region}: {type(exc).__name__}"
            LOGGER.warning(msg, exc_info=True)
            errors.append(msg)

    await _set_cursor(account_id, last_pull_end=end_dt.isoformat())
    return {
        "ok": not errors or total_ingested > 0,
        "ingested": total_ingested,
        "regions": regions,
        "errors": errors,
    }


async def _aws_cloudwatch_fetch(
    client,
    *,
    namespace: str,
    metric_names: list[str],
    resource_dimension_name: str,
    resource_ids: list[str],
    start: datetime,
    end: datetime,
    period_seconds: int,
) -> list[dict]:
    import asyncio

    def _run() -> list[dict]:
        records: list[dict] = []
        for metric_name in metric_names:
            for resource_id in resource_ids:
                if len(records) >= _MAX_RECORDS_PER_PULL:
                    return records
                resp = client.get_metric_statistics(
                    Namespace=namespace,
                    MetricName=metric_name,
                    Dimensions=[{"Name": resource_dimension_name, "Value": resource_id}],
                    StartTime=start,
                    EndTime=end,
                    Period=period_seconds,
                    Statistics=["Average", "Sum", "Maximum"],
                )
                datapoints = resp.get("Datapoints", [])
                for dp in datapoints:
                    records.append(
                        {
                            "MetricName": metric_name,
                            "Namespace": namespace,
                            "Dimensions": [{"Name": resource_dimension_name, "Value": resource_id}],
                            "Timestamp": dp.get("Timestamp"),
                            "Average": dp.get("Average"),
                            "Sum": dp.get("Sum"),
                            "Maximum": dp.get("Maximum"),
                            "Unit": dp.get("Unit") or "Count",
                            "direction": _metric_direction(metric_name),
                        }
                    )
                    if len(records) >= _MAX_RECORDS_PER_PULL:
                        return records
        return records

    return await asyncio.to_thread(_run)


async def pull_azure_traffic_metrics(account: dict, *, lookback_minutes: int = _DEFAULT_LOOKBACK_MINUTES) -> dict:
    """Pull network traffic metrics from Azure Monitor."""
    account_id = int(account["id"])
    auth = _parse_auth_config(account)
    resource_ids = _parse_list(auth.get("resource_ids"))
    metric_names = _parse_list(auth.get("metric_names")) or ["BytesIn", "BytesOut", "PacketsIn", "PacketsOut"]

    if not resource_ids:
        return {"ok": False, "error": "missing_resource_ids", "ingested": 0}

    try:
        from azure.monitor.query import MetricsQueryClient  # noqa: F401
    except ImportError:
        return {"ok": False, "error": "azure_monitor_query_not_installed", "ingested": 0}

    cursor = await _get_cursor(account_id)
    start_dt, end_dt = _window(cursor, lookback_minutes=lookback_minutes)

    total_ingested = 0
    errors: list[str] = []

    try:
        client = _build_azure_metrics_client(auth)
        records = await _azure_monitor_fetch(
            client,
            resource_ids=resource_ids,
            metric_names=metric_names,
            start=start_dt,
            end=end_dt,
        )
        if records:
            normalized = _normalize_azure_traffic_metric_records(records[:_MAX_RECORDS_PER_PULL])
            if normalized:
                rows = _build_traffic_metric_rows_for_ingest(
                    account_id,
                    "azure",
                    normalized,
                    source="scheduled_pull",
                )
                total_ingested = await db.create_cloud_traffic_metrics_batch(rows)
    except Exception as exc:
        msg = f"Azure traffic pull failed: {type(exc).__name__}"
        LOGGER.warning(msg, exc_info=True)
        errors.append(msg)

    await _set_cursor(account_id, last_pull_end=end_dt.isoformat())
    return {
        "ok": not errors or total_ingested > 0,
        "ingested": total_ingested,
        "errors": errors,
    }


def _build_azure_metrics_client(auth: dict):
    from azure.monitor.query import MetricsQueryClient

    credential = None
    client_id = str(auth.get("client_id") or "").strip()
    client_secret = str(auth.get("client_secret") or "").strip()
    tenant_id = str(auth.get("tenant_id") or "").strip()
    if client_id and client_secret and tenant_id:
        try:
            from azure.identity import ClientSecretCredential
            credential = ClientSecretCredential(tenant_id=tenant_id, client_id=client_id, client_secret=client_secret)
        except ImportError:
            raise ImportError("azure-identity is required for explicit service principal auth")
    if credential is None:
        try:
            from azure.identity import DefaultAzureCredential
            credential = DefaultAzureCredential()
        except ImportError:
            raise ImportError("azure-identity is required for Azure Monitor puller")
    return MetricsQueryClient(credential)


async def _azure_monitor_fetch(
    client,
    *,
    resource_ids: list[str],
    metric_names: list[str],
    start: datetime,
    end: datetime,
) -> list[dict]:
    import asyncio

    def _run() -> list[dict]:
        records: list[dict] = []
        timespan = (start, end)
        for resource_id in resource_ids:
            if len(records) >= _MAX_RECORDS_PER_PULL:
                break
            result = client.query_resource(
                resource_id,
                metric_names=metric_names,
                timespan=timespan,
            )
            metrics = getattr(result, "metrics", []) or []
            for metric in metrics:
                metric_name = getattr(getattr(metric, "name", None), "value", "")
                namespace = getattr(getattr(metric, "name", None), "namespace", "azure.monitor")
                timeseries = getattr(metric, "timeseries", []) or []
                for series in timeseries:
                    for point in getattr(series, "data", []) or []:
                        total = getattr(point, "total", None)
                        average = getattr(point, "average", None)
                        maximum = getattr(point, "maximum", None)
                        value = total if total is not None else average
                        if value is None:
                            value = maximum
                        if value is None:
                            continue
                        records.append(
                            {
                                "metricName": metric_name,
                                "namespace": namespace,
                                "resourceId": resource_id,
                                "timeStamp": getattr(point, "timestamp", None),
                                "total": total,
                                "average": average,
                                "maximum": maximum,
                                "unit": str(getattr(metric, "unit", "") or ""),
                                "direction": _metric_direction(metric_name),
                            }
                        )
                        if len(records) >= _MAX_RECORDS_PER_PULL:
                            return records
        return records

    return await asyncio.to_thread(_run)


async def pull_gcp_traffic_metrics(account: dict, *, lookback_minutes: int = _DEFAULT_LOOKBACK_MINUTES) -> dict:
    """Pull network traffic metrics from GCP Cloud Monitoring."""
    account_id = int(account["id"])
    auth = _parse_auth_config(account)
    project_id = str(auth.get("project_id") or "").strip()
    metric_types = _parse_list(auth.get("metric_types")) or [
        "compute.googleapis.com/instance/network/received_bytes_count",
        "compute.googleapis.com/instance/network/sent_bytes_count",
        "compute.googleapis.com/instance/network/received_packets_count",
        "compute.googleapis.com/instance/network/sent_packets_count",
    ]

    if not project_id:
        return {"ok": False, "error": "missing_project_id", "ingested": 0}

    try:
        from google.cloud import monitoring_v3  # noqa: F401
    except ImportError:
        return {"ok": False, "error": "google_cloud_monitoring_not_installed", "ingested": 0}

    cursor = await _get_cursor(account_id)
    start_dt, end_dt = _window(cursor, lookback_minutes=lookback_minutes)

    total_ingested = 0
    errors: list[str] = []

    try:
        client = _build_gcp_monitoring_client(auth)
        records = await _gcp_monitoring_fetch(
            client,
            project_id=project_id,
            metric_types=metric_types,
            start=start_dt,
            end=end_dt,
        )
        if records:
            normalized = _normalize_gcp_traffic_metric_records(records[:_MAX_RECORDS_PER_PULL])
            if normalized:
                rows = _build_traffic_metric_rows_for_ingest(
                    account_id,
                    "gcp",
                    normalized,
                    source="scheduled_pull",
                )
                total_ingested = await db.create_cloud_traffic_metrics_batch(rows)
    except Exception as exc:
        msg = f"GCP traffic pull failed: {type(exc).__name__}"
        LOGGER.warning(msg, exc_info=True)
        errors.append(msg)

    await _set_cursor(account_id, last_pull_end=end_dt.isoformat())
    return {
        "ok": not errors or total_ingested > 0,
        "ingested": total_ingested,
        "errors": errors,
    }


def _build_gcp_monitoring_client(auth: dict):
    from google.cloud import monitoring_v3

    sa_json = auth.get("service_account_json")
    creds_file = str(auth.get("credentials_file") or "").strip()

    if isinstance(sa_json, dict):
        from google.oauth2 import service_account

        credentials = service_account.Credentials.from_service_account_info(sa_json)
        return monitoring_v3.MetricServiceClient(credentials=credentials)

    if isinstance(sa_json, str) and sa_json.strip():
        try:
            info = json.loads(sa_json)
            if isinstance(info, dict):
                from google.oauth2 import service_account

                credentials = service_account.Credentials.from_service_account_info(info)
                return monitoring_v3.MetricServiceClient(credentials=credentials)
        except json.JSONDecodeError:
            pass

    if creds_file:
        from google.oauth2 import service_account

        credentials = service_account.Credentials.from_service_account_file(creds_file)
        return monitoring_v3.MetricServiceClient(credentials=credentials)

    return monitoring_v3.MetricServiceClient()


async def _gcp_monitoring_fetch(
    client,
    *,
    project_id: str,
    metric_types: list[str],
    start: datetime,
    end: datetime,
) -> list[dict]:
    import asyncio

    def _run() -> list[dict]:
        from google.cloud import monitoring_v3

        project_name = f"projects/{project_id}"
        interval = monitoring_v3.TimeInterval(
            {
                "start_time": {"seconds": int(start.timestamp())},
                "end_time": {"seconds": int(end.timestamp())},
            }
        )
        records: list[dict] = []
        for metric_type in metric_types:
            if len(records) >= _MAX_RECORDS_PER_PULL:
                break
            filter_str = f'metric.type = "{metric_type}"'
            request = monitoring_v3.ListTimeSeriesRequest(
                name=project_name,
                filter=filter_str,
                interval=interval,
                view=monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
            )
            for ts in client.list_time_series(request=request):
                points = []
                for point in getattr(ts, "points", []) or []:
                    value = getattr(point, "value", None)
                    points.append(
                        {
                            "interval": {
                                "startTime": _gcp_ts_iso(getattr(point.interval, "start_time", None)),
                                "endTime": _gcp_ts_iso(getattr(point.interval, "end_time", None)),
                            },
                            "value": {
                                "doubleValue": getattr(value, "double_value", None),
                                "int64Value": getattr(value, "int64_value", None),
                            },
                        }
                    )
                records.append(
                    {
                        "metric": {
                            "type": getattr(getattr(ts, "metric", None), "type", metric_type),
                            "labels": dict(getattr(getattr(ts, "metric", None), "labels", {}) or {}),
                        },
                        "resource": {
                            "type": getattr(getattr(ts, "resource", None), "type", ""),
                            "labels": dict(getattr(getattr(ts, "resource", None), "labels", {}) or {}),
                        },
                        "points": points,
                        "metric_namespace": "gcp.monitoring",
                        "direction": _metric_direction(metric_type),
                    }
                )
                if len(records) >= _MAX_RECORDS_PER_PULL:
                    return records
        return records

    return await asyncio.to_thread(_run)


def _gcp_ts_iso(ts_obj) -> str:
    if not ts_obj:
        return datetime.now(UTC).isoformat()
    sec = getattr(ts_obj, "seconds", 0) or 0
    nanos = getattr(ts_obj, "nanos", 0) or 0
    return datetime.fromtimestamp(float(sec) + (float(nanos) / 1_000_000_000.0), tz=UTC).isoformat()


_PULLERS = {
    "aws": pull_aws_traffic_metrics,
    "azure": pull_azure_traffic_metrics,
    "gcp": pull_gcp_traffic_metrics,
}


async def pull_traffic_metrics_for_account(account: dict, *, lookback_minutes: int = _DEFAULT_LOOKBACK_MINUTES) -> dict:
    provider = str(account.get("provider") or "").strip().lower()
    puller = _PULLERS.get(provider)
    if not puller:
        return {"ok": False, "error": f"unsupported_provider:{provider}", "ingested": 0}
    return await puller(account, lookback_minutes=lookback_minutes)


async def pull_traffic_metrics_all_accounts(*, lookback_minutes: int = _DEFAULT_LOOKBACK_MINUTES) -> dict:
    accounts = await db.list_cloud_accounts(enabled_only=True)
    results: dict[int, dict] = {}
    total_ingested = 0

    for account in accounts:
        account_id = int(account["id"])
        provider = str(account.get("provider") or "").strip().lower()
        auth = _parse_auth_config(account)

        if provider == "aws" and not _parse_list(auth.get("resource_ids")):
            continue
        if provider == "azure" and not _parse_list(auth.get("resource_ids")):
            continue
        if provider == "gcp" and not str(auth.get("project_id") or "").strip():
            continue

        try:
            result = await pull_traffic_metrics_for_account(account, lookback_minutes=lookback_minutes)
            results[account_id] = result
            total_ingested += result.get("ingested", 0)
        except Exception as exc:
            LOGGER.warning(
                "cloud traffic metric pull failed account_id=%s: %s",
                account_id,
                type(exc).__name__,
                exc_info=True,
            )
            results[account_id] = {"ok": False, "error": str(type(exc).__name__), "ingested": 0}

    return {
        "accounts_processed": len(results),
        "total_ingested": total_ingested,
        "results": results,
    }


def _build_boto3_session(auth: dict):
    import boto3

    kwargs: dict[str, Any] = {}
    if auth.get("profile_name"):
        kwargs["profile_name"] = str(auth["profile_name"])
    if auth.get("access_key_id"):
        kwargs["aws_access_key_id"] = str(auth["access_key_id"])
    if auth.get("secret_access_key"):
        kwargs["aws_secret_access_key"] = str(auth["secret_access_key"])
    if auth.get("session_token"):
        kwargs["aws_session_token"] = str(auth["session_token"])
    session = boto3.Session(**kwargs)

    role_arn = str(auth.get("role_arn") or "").strip()
    if role_arn:
        sts = session.client("sts")
        assume_args: dict[str, str] = {
            "RoleArn": role_arn,
            "RoleSessionName": str(auth.get("role_session_name") or "plexus-metric-puller"),
        }
        external_id = str(auth.get("external_id") or "").strip()
        if external_id:
            assume_args["ExternalId"] = external_id
        creds = sts.assume_role(**assume_args)["Credentials"]
        session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    return session


def _parse_auth_config(account: dict) -> dict:
    raw = account.get("auth_config_json") or account.get("auth_config") or "{}"
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return {}
        try:
            parsed = json.loads(stripped)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def _parse_regions(account: dict) -> list[str]:
    raw = str(account.get("region_scope") or "").strip()
    if not raw:
        return ["us-east-1"]
    return [r.strip() for r in raw.split(",") if r.strip()]


def _parse_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        if text.startswith("["):
            try:
                parsed = json.loads(text)
                if isinstance(parsed, list):
                    return [str(v).strip() for v in parsed if str(v).strip()]
            except Exception:
                pass
        return [v.strip() for v in text.split(",") if v.strip()]
    return []


def _metric_direction(metric_name: str) -> str:
    name = str(metric_name or "").strip().lower()
    if any(token in name for token in ("in", "ingress", "received", "rx")):
        return "in"
    if any(token in name for token in ("out", "egress", "sent", "tx")):
        return "out"
    return ""
