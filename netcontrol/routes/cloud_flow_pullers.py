"""
cloud_flow_pullers.py -- Scheduled flow-log pullers for each cloud provider.

Pulls flow logs from:
  - AWS: CloudWatch Logs Insights / S3 (VPC Flow Logs)
  - Azure: Blob Storage (NSG Flow Logs)
  - GCP: Cloud Logging (VPC Flow Logs)

Records are normalised and fed into the existing flow-log ingest pipeline
(``create_flow_records_batch`` → shared ``flow_records`` table).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import routes.database as db

from netcontrol.routes.cloud_visibility import (
    _FLOW_TYPE_BY_PROVIDER,
    _build_flow_rows_for_ingest,
    _normalize_aws_flow_records,
    _normalize_azure_flow_records,
    _normalize_gcp_flow_records,
    _safe_int,
)
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.cloud_flow_pullers")

# Default look-back when no watermark exists (minutes).
_DEFAULT_LOOKBACK_MINUTES = 15

# Maximum records per pull cycle to avoid memory pressure.
_MAX_RECORDS_PER_PULL = 10_000


# ═══════════════════════════════════════════════════════════════════════════
# Watermark helpers — per-account cursor stored in cloud_flow_sync_cursors
# ═══════════════════════════════════════════════════════════════════════════

async def _get_cursor(account_id: int) -> dict:
    row = await db.get_cloud_flow_sync_cursor(account_id)
    return row or {}


async def _set_cursor(account_id: int, *, last_pull_end: str, extra: dict | None = None) -> None:
    await db.upsert_cloud_flow_sync_cursor(
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
    # Clamp: never go further back than 24 h
    floor = now - timedelta(hours=24)
    if start < floor:
        start = floor
    return start, end


# ═══════════════════════════════════════════════════════════════════════════
# AWS puller — CloudWatch Logs Insights or S3
# ═══════════════════════════════════════════════════════════════════════════

async def pull_aws_flow_logs(account: dict) -> dict:
    """Pull VPC Flow Logs from AWS CloudWatch Logs Insights.

    Required auth_config keys:
      - log_group_name (str): CloudWatch Logs group, e.g. ``/aws/vpc/flow-logs``
      - (optional) s3_bucket / s3_prefix for S3-based flow logs (future)

    Standard boto3 credential keys (access_key_id, secret_access_key,
    role_arn, profile_name) are read from the account's auth_config.
    """
    account_id = int(account["id"])
    auth = _parse_auth_config(account)
    log_group = str(auth.get("log_group_name") or "").strip()
    if not log_group:
        return {"ok": False, "error": "missing_log_group_name", "ingested": 0}

    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        return {"ok": False, "error": "boto3_not_installed", "ingested": 0}

    session = _build_boto3_session(auth)
    regions = _parse_regions(account)
    cursor = await _get_cursor(account_id)
    start_dt, end_dt = _window(cursor)

    total_ingested = 0
    errors: list[str] = []

    for region in regions:
        try:
            client = session.client("logs", region_name=region)
            records = await _cw_insights_query(
                client, log_group, start_dt, end_dt,
            )
            if not records:
                continue
            normalized = _normalize_aws_flow_records(records)
            if not normalized:
                continue
            # Cap per region
            normalized = normalized[:_MAX_RECORDS_PER_PULL]
            rows = _build_flow_rows_for_ingest(account_id, "aws", normalized)
            count = await db.create_flow_records_batch(rows)
            total_ingested += count
        except (BotoCoreError, ClientError) as exc:
            msg = f"AWS flow pull failed region={region}: {type(exc).__name__}"
            LOGGER.warning(msg)
            errors.append(msg)
        except Exception as exc:
            msg = f"AWS flow pull unexpected error region={region}: {type(exc).__name__}"
            LOGGER.warning(msg, exc_info=True)
            errors.append(msg)

    await _set_cursor(account_id, last_pull_end=end_dt.isoformat())

    return {
        "ok": not errors or total_ingested > 0,
        "ingested": total_ingested,
        "regions": regions,
        "errors": errors,
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
            "RoleSessionName": str(auth.get("role_session_name") or "plexus-flow-puller"),
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


async def _cw_insights_query(
    client,
    log_group: str,
    start: datetime,
    end: datetime,
) -> list[dict]:
    """Run a CloudWatch Logs Insights query for VPC Flow Log fields.

    This is executed in the calling event loop via ``asyncio.to_thread``
    because the boto3 SDK is synchronous.
    """
    import asyncio

    query = (
        "fields @timestamp, srcAddr, dstAddr, srcPort, dstPort, protocol, "
        "bytes, packets, action, flowDirection, interfaceId, vpcId, subnetId "
        f"| sort @timestamp asc | limit {_MAX_RECORDS_PER_PULL}"
    )

    def _run():
        resp = client.start_query(
            logGroupName=log_group,
            startTime=int(start.timestamp()),
            endTime=int(end.timestamp()),
            queryString=query,
        )
        query_id = resp["queryId"]

        import time as _time

        # Poll until complete (max ~60s).
        for _ in range(60):
            result = client.get_query_results(queryId=query_id)
            status = result.get("status", "")
            if status in ("Complete", "Failed", "Cancelled", "Timeout"):
                break
            _time.sleep(1)

        if result.get("status") != "Complete":
            return []

        rows: list[dict] = []
        for row_fields in result.get("results", []):
            record: dict[str, str] = {}
            for field in row_fields:
                fname = str(field.get("field") or "").strip()
                fval = str(field.get("value") or "").strip()
                if fname.startswith("@"):
                    fname = fname[1:]
                record[fname] = fval
            # Map CW Insights field names → normalizer expected keys
            mapped: dict[str, Any] = {
                "srcaddr": record.get("srcAddr", ""),
                "dstaddr": record.get("dstAddr", ""),
                "srcport": record.get("srcPort", ""),
                "dstport": record.get("dstPort", ""),
                "protocol": record.get("protocol", ""),
                "bytes": record.get("bytes", "0"),
                "packets": record.get("packets", "0"),
                "action": record.get("action", ""),
                "flow-direction": record.get("flowDirection", ""),
                "interface-id": record.get("interfaceId", ""),
                "vpc-id": record.get("vpcId", ""),
                "subnet-id": record.get("subnetId", ""),
                "start": record.get("timestamp", ""),
            }
            rows.append(mapped)
        return rows

    return await asyncio.to_thread(_run)


# ═══════════════════════════════════════════════════════════════════════════
# Azure puller — Blob Storage NSG Flow Logs
# ═══════════════════════════════════════════════════════════════════════════

async def pull_azure_flow_logs(account: dict) -> dict:
    """Pull NSG Flow Logs from Azure Blob Storage.

    Required auth_config keys:
      - storage_account_name (str)
      - container_name (str): blob container, e.g. ``insights-logs-networksecuritygroupflowevent``
      - (optional) storage_account_key or use DefaultAzureCredential
      - subscription_id (str)
    """
    account_id = int(account["id"])
    auth = _parse_auth_config(account)
    storage_account = str(auth.get("storage_account_name") or "").strip()
    container = str(auth.get("container_name") or "").strip()
    if not storage_account or not container:
        return {"ok": False, "error": "missing_storage_config", "ingested": 0}

    try:
        from azure.storage.blob import BlobServiceClient
    except ImportError:
        return {"ok": False, "error": "azure_storage_blob_not_installed", "ingested": 0}

    cursor = await _get_cursor(account_id)
    start_dt, end_dt = _window(cursor)

    total_ingested = 0
    errors: list[str] = []

    try:
        blob_client = _build_azure_blob_client(auth, storage_account)
        container_client = blob_client.get_container_client(container)

        # NSG flow logs are stored with time-partitioned blob names.
        # List blobs modified within the window.
        prefix = _azure_flow_log_prefix(start_dt)
        records: list[dict] = []

        async def _list_and_read():
            import asyncio
            return await asyncio.to_thread(
                _read_azure_blobs, container_client, prefix, start_dt, end_dt,
            )

        records = await _list_and_read()

        if records:
            normalized = _normalize_azure_flow_records(records[:_MAX_RECORDS_PER_PULL])
            if normalized:
                rows = _build_flow_rows_for_ingest(account_id, "azure", normalized)
                total_ingested = await db.create_flow_records_batch(rows)

    except Exception as exc:
        msg = f"Azure flow pull failed: {type(exc).__name__}"
        LOGGER.warning(msg, exc_info=True)
        errors.append(msg)

    await _set_cursor(account_id, last_pull_end=end_dt.isoformat())

    return {
        "ok": not errors or total_ingested > 0,
        "ingested": total_ingested,
        "errors": errors,
    }


def _build_azure_blob_client(auth: dict, storage_account: str):
    from azure.storage.blob import BlobServiceClient

    account_key = str(auth.get("storage_account_key") or "").strip()
    if account_key:
        account_url = f"https://{storage_account}.blob.core.windows.net"
        return BlobServiceClient(account_url=account_url, credential=account_key)

    # Fall back to DefaultAzureCredential (managed identity / env vars).
    try:
        from azure.identity import DefaultAzureCredential
        credential = DefaultAzureCredential()
        account_url = f"https://{storage_account}.blob.core.windows.net"
        return BlobServiceClient(account_url=account_url, credential=credential)
    except ImportError:
        raise ImportError("azure-identity is required when storage_account_key is not provided")


def _azure_flow_log_prefix(dt: datetime) -> str:
    """Build a blob name prefix for the given date partition."""
    return f"resourceId=/y={dt.year}/m={dt.month:02d}/d={dt.day:02d}/"


def _read_azure_blobs(container_client, prefix: str, start: datetime, end: datetime) -> list[dict]:
    """Read and parse NSG flow log JSON blobs within the time window."""
    records: list[dict] = []
    try:
        blobs = container_client.list_blobs(name_starts_with=prefix)
        for blob_props in blobs:
            if len(records) >= _MAX_RECORDS_PER_PULL:
                break
            blob_data = container_client.download_blob(blob_props.name).readall()
            try:
                parsed = json.loads(blob_data)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue

            # NSG flow log JSON structure: { records: [ { properties: { flows: [...] } } ] }
            for log_record in parsed.get("records", []):
                props = log_record.get("properties", {})
                for flow_group in props.get("flows", []):
                    rule_name = str(flow_group.get("rule") or "")
                    for flow_set in flow_group.get("flows", []):
                        mac = str(flow_set.get("mac") or "")
                        for flow_tuple in flow_set.get("flowTuples", []):
                            records.append({
                                "flow_tuples": [flow_tuple],
                                "rule_name": rule_name,
                                "region": str(log_record.get("location") or ""),
                                "resource_id": str(log_record.get("resourceId") or ""),
                            })
    except Exception:
        LOGGER.debug("Azure blob list/read failed", exc_info=True)
    return records


# ═══════════════════════════════════════════════════════════════════════════
# GCP puller — Cloud Logging export
# ═══════════════════════════════════════════════════════════════════════════

async def pull_gcp_flow_logs(account: dict) -> dict:
    """Pull VPC Flow Logs from GCP Cloud Logging.

    Required auth_config keys:
      - project_id (str): GCP project ID
      - (optional) service_account_json / credentials_file for auth
    """
    account_id = int(account["id"])
    auth = _parse_auth_config(account)
    project_id = str(auth.get("project_id") or "").strip()
    if not project_id:
        return {"ok": False, "error": "missing_project_id", "ingested": 0}

    try:
        from google.cloud import logging as gcp_logging
    except ImportError:
        return {"ok": False, "error": "google_cloud_logging_not_installed", "ingested": 0}

    cursor = await _get_cursor(account_id)
    start_dt, end_dt = _window(cursor)

    total_ingested = 0
    errors: list[str] = []

    try:
        client = _build_gcp_logging_client(auth, project_id)
        records = await _gcp_logging_query(client, project_id, start_dt, end_dt)

        if records:
            normalized = _normalize_gcp_flow_records(records[:_MAX_RECORDS_PER_PULL])
            if normalized:
                rows = _build_flow_rows_for_ingest(account_id, "gcp", normalized)
                total_ingested = await db.create_flow_records_batch(rows)

    except Exception as exc:
        msg = f"GCP flow pull failed: {type(exc).__name__}"
        LOGGER.warning(msg, exc_info=True)
        errors.append(msg)

    await _set_cursor(account_id, last_pull_end=end_dt.isoformat())

    return {
        "ok": not errors or total_ingested > 0,
        "ingested": total_ingested,
        "errors": errors,
    }


def _build_gcp_logging_client(auth: dict, project_id: str):
    from google.cloud import logging as gcp_logging

    sa_json = auth.get("service_account_json")
    creds_file = str(auth.get("credentials_file") or "").strip()

    if isinstance(sa_json, dict):
        from google.oauth2 import service_account
        credentials = service_account.Credentials.from_service_account_info(sa_json)
        return gcp_logging.Client(project=project_id, credentials=credentials)
    if isinstance(sa_json, str) and sa_json.strip():
        try:
            info = json.loads(sa_json)
            if isinstance(info, dict):
                from google.oauth2 import service_account
                credentials = service_account.Credentials.from_service_account_info(info)
                return gcp_logging.Client(project=project_id, credentials=credentials)
        except json.JSONDecodeError:
            pass
    if creds_file:
        from google.oauth2 import service_account
        credentials = service_account.Credentials.from_service_account_file(creds_file)
        return gcp_logging.Client(project=project_id, credentials=credentials)

    # Application Default Credentials
    return gcp_logging.Client(project=project_id)


async def _gcp_logging_query(
    client, project_id: str, start: datetime, end: datetime,
) -> list[dict]:
    """Query VPC Flow Logs from Cloud Logging."""
    import asyncio

    def _run():
        start_str = start.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_str = end.strftime("%Y-%m-%dT%H:%M:%SZ")
        filter_str = (
            'resource.type="gce_subnetwork" '
            'logName:"compute.googleapis.com%2Fvpc_flows" '
            f'timestamp>="{start_str}" '
            f'timestamp<="{end_str}"'
        )
        entries = client.list_entries(
            filter_=filter_str,
            page_size=_MAX_RECORDS_PER_PULL,
            max_results=_MAX_RECORDS_PER_PULL,
        )
        records: list[dict] = []
        for entry in entries:
            if len(records) >= _MAX_RECORDS_PER_PULL:
                break
            payload = entry.payload if hasattr(entry, "payload") else {}
            if not isinstance(payload, dict):
                continue
            conn = payload.get("connection", {})
            record: dict[str, Any] = {
                "connection": conn,
                "bytes_sent": _safe_int(payload.get("bytes_sent")),
                "bytes_received": _safe_int(payload.get("bytes_received")),
                "packets_sent": _safe_int(payload.get("packets_sent")),
                "packets_received": _safe_int(payload.get("packets_received")),
                "start_time": payload.get("start_time") or str(entry.timestamp or ""),
                "end_time": payload.get("end_time") or str(entry.timestamp or ""),
                "reporter": payload.get("reporter", ""),
                "disposition": payload.get("disposition", ""),
                "project_id": project_id,
            }
            # Enrich from resource labels
            resource = entry.resource if hasattr(entry, "resource") else None
            if resource and hasattr(resource, "labels"):
                labels = resource.labels or {}
                record["vpc_id"] = str(labels.get("network") or labels.get("subnetwork_name") or "")
                record["subnetwork"] = str(labels.get("subnetwork_name") or "")
                record["region"] = str(labels.get("location") or "")
            records.append(record)
        return records

    return await asyncio.to_thread(_run)


# ═══════════════════════════════════════════════════════════════════════════
# Dispatcher
# ═══════════════════════════════════════════════════════════════════════════

_PULLERS = {
    "aws": pull_aws_flow_logs,
    "azure": pull_azure_flow_logs,
    "gcp": pull_gcp_flow_logs,
}


async def pull_flow_logs_for_account(account: dict) -> dict:
    """Pull flow logs for a single cloud account using the correct provider puller."""
    provider = str(account.get("provider") or "").strip().lower()
    puller = _PULLERS.get(provider)
    if not puller:
        return {"ok": False, "error": f"unsupported_provider:{provider}", "ingested": 0}
    return await puller(account)


async def pull_flow_logs_all_accounts() -> dict:
    """Iterate all enabled cloud accounts and pull flow logs.

    Returns a summary dict with per-account results.
    """
    accounts = await db.list_cloud_accounts(enabled_only=True)
    results: dict[int, dict] = {}
    total_ingested = 0

    for account in accounts:
        account_id = int(account["id"])
        provider = str(account.get("provider") or "").strip().lower()
        flow_config = _parse_auth_config(account)

        # Skip accounts that have no flow-log source configured
        if provider == "aws" and not flow_config.get("log_group_name"):
            continue
        if provider == "azure" and not (
            flow_config.get("storage_account_name") and flow_config.get("container_name")
        ):
            continue
        if provider == "gcp" and not flow_config.get("project_id"):
            continue

        try:
            result = await pull_flow_logs_for_account(account)
            results[account_id] = result
            total_ingested += result.get("ingested", 0)
        except Exception as exc:
            LOGGER.warning(
                "cloud flow pull failed account_id=%s: %s",
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


# ═══════════════════════════════════════════════════════════════════════════
# Shared helpers
# ═══════════════════════════════════════════════════════════════════════════

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
