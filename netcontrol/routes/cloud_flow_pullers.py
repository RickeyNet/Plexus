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

import asyncio
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

# Accounts pulled concurrently per cycle (one hung provider must not stall
# the rest, but don't hammer every provider at once either).
_MAX_CONCURRENT_ACCOUNTS = 4

# Serializes manual triggers against the scheduled loop per account so two
# pulls can't race the same watermark cursor and double-ingest a window.
_ACCOUNT_LOCKS: dict[int, asyncio.Lock] = {}


def _account_lock(account_id: int) -> asyncio.Lock:
    lock = _ACCOUNT_LOCKS.get(account_id)
    if lock is None:
        lock = _ACCOUNT_LOCKS[account_id] = asyncio.Lock()
    return lock


def _boto3_client_config():
    from botocore.config import Config

    return Config(
        connect_timeout=10,
        read_timeout=60,
        retries={"max_attempts": 4, "mode": "adaptive"},
    )


# ═══════════════════════════════════════════════════════════════════════════
# Watermark helpers - per-account cursor stored in cloud_flow_sync_cursors
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


def _parse_cursor_extra(cursor: dict) -> dict:
    raw = cursor.get("extra_json")
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def _parse_watermark(value) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except Exception:
        return None


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
# AWS puller - CloudWatch Logs Insights or S3
# ═══════════════════════════════════════════════════════════════════════════

async def pull_aws_flow_logs(account: dict, *, lookback_minutes: int = _DEFAULT_LOOKBACK_MINUTES) -> dict:
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

    import asyncio

    # Session build may call sts.assume_role (blocking network I/O)
    session = await asyncio.to_thread(_build_boto3_session, auth)
    regions = _parse_regions(account)
    cursor = await _get_cursor(account_id)
    extra = _parse_cursor_extra(cursor)
    regions_set = set(regions)
    region_marks: dict[str, str] = {
        k: v
        for k, v in (extra.get("regions") or {}).items()
        if isinstance(v, str) and k in regions_set
    }
    global_start, end_dt = _window(cursor, lookback_minutes=lookback_minutes)

    total_ingested = 0
    errors: list[str] = []
    warnings: list[str] = []

    for region in regions:
        # Each region keeps its own watermark so a failure in one region
        # doesn't force re-pulling (and duplicating) the others.
        region_start = _parse_watermark(region_marks.get(region)) or global_start
        if region_start >= end_dt:
            continue
        try:
            client = session.client("logs", region_name=region, config=_boto3_client_config())
            records, truncated = await _cw_insights_query(
                client, log_group, region_start, end_dt,
            )
            region_end = end_dt
            if truncated:
                # Advance only to the last returned record (results are sorted
                # ascending) so the remainder is picked up next cycle.
                last_ts = _parse_insights_timestamp(records[-1].get("start")) if records else None
                if last_ts and region_start < last_ts < end_dt:
                    region_end = last_ts
                warnings.append(
                    f"region={region}: results truncated at {_MAX_RECORDS_PER_PULL}"
                )
            if records:
                normalized = _normalize_aws_flow_records(records)
                if normalized:
                    rows = _build_flow_rows_for_ingest(account_id, "aws", normalized)
                    total_ingested += await db.create_flow_records_batch(rows)
            region_marks[region] = region_end.isoformat()
        except (BotoCoreError, ClientError) as exc:
            msg = f"AWS flow pull failed region={region}: {type(exc).__name__}"
            LOGGER.warning(msg)
            errors.append(msg)
        except Exception as exc:
            msg = f"AWS flow pull unexpected error region={region}: {type(exc).__name__}"
            LOGGER.warning(msg, exc_info=True)
            errors.append(msg)

    # Failed regions keep their old watermark (or the global one) so the
    # missed window is retried next cycle instead of silently skipped.
    watermarks = [_parse_watermark(v) for v in region_marks.values()]
    if errors:
        watermarks.append(_parse_watermark(cursor.get("last_pull_end")) or global_start)
    valid_marks = [w for w in watermarks if w]
    if valid_marks:
        await _set_cursor(
            account_id,
            last_pull_end=min(valid_marks).isoformat(),
            extra={"regions": region_marks},
        )

    return {
        "ok": not errors,
        "partial": bool(errors) and total_ingested > 0,
        "ingested": total_ingested,
        "regions": regions,
        "errors": errors,
        "warnings": warnings,
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
        from botocore.config import Config

        sts = session.client("sts", config=Config(
            connect_timeout=10, read_timeout=30, retries={"max_attempts": 2},
        ))
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
) -> tuple[list[dict], bool]:
    """Run a CloudWatch Logs Insights query for VPC Flow Log fields.

    Returns ``(records, truncated)``. Raises on query failure or timeout so
    the caller can keep the watermark and retry the window.

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

        status = str(result.get("status") or "")
        if status != "Complete":
            if status == "Running" or not status:
                # Still running after the poll budget: cancel so we don't leak
                # toward the 30-concurrent-Insights-queries account limit.
                try:
                    client.stop_query(queryId=query_id)
                except Exception:
                    LOGGER.debug("stop_query failed for %s", query_id, exc_info=True)
            raise RuntimeError(f"insights_query_{(status or 'timeout').lower()}")

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
        return rows, len(rows) >= _MAX_RECORDS_PER_PULL

    return await asyncio.to_thread(_run)


def _parse_insights_timestamp(value) -> datetime | None:
    """Parse a CloudWatch Insights @timestamp value (``YYYY-MM-DD HH:MM:SS.mmm``,
    UTC) or an epoch-seconds string."""
    text = str(value or "").strip()
    if not text:
        return None
    if text.isdigit():
        try:
            return datetime.fromtimestamp(int(text), tz=UTC)
        except (ValueError, OSError, OverflowError):
            return None
    try:
        parsed = datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except ValueError:
        return None


# ═══════════════════════════════════════════════════════════════════════════
# Azure puller - Blob Storage NSG Flow Logs
# ═══════════════════════════════════════════════════════════════════════════

async def pull_azure_flow_logs(account: dict, *, lookback_minutes: int = _DEFAULT_LOOKBACK_MINUTES) -> dict:
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
    start_dt, end_dt = _window(cursor, lookback_minutes=lookback_minutes)

    total_ingested = 0
    errors: list[str] = []
    warnings: list[str] = []

    try:
        blob_client = _build_azure_blob_client(auth, storage_account)
        container_client = blob_client.get_container_client(container)

        async def _list_and_read():
            import asyncio
            return await asyncio.to_thread(
                _read_azure_blobs, container_client, start_dt, end_dt,
            )

        records, truncated = await _list_and_read()
        if truncated:
            warnings.append(f"results truncated at {_MAX_RECORDS_PER_PULL}")

        if records:
            normalized = _normalize_azure_flow_records(records)
            if normalized:
                rows = _build_flow_rows_for_ingest(account_id, "azure", normalized)
                total_ingested = await db.create_flow_records_batch(rows)

        # Advance the watermark only on success so a failed window is
        # retried next cycle instead of silently skipped.
        await _set_cursor(account_id, last_pull_end=end_dt.isoformat())

    except Exception as exc:
        msg = f"Azure flow pull failed: {type(exc).__name__}"
        LOGGER.warning(msg, exc_info=True)
        errors.append(msg)

    return {
        "ok": not errors,
        "partial": False,
        "ingested": total_ingested,
        "errors": errors,
        "warnings": warnings,
    }


def _build_azure_blob_client(auth: dict, storage_account: str):
    from azure.storage.blob import BlobServiceClient

    account_key = str(auth.get("storage_account_key") or "").strip()
    account_url = f"https://{storage_account}.blob.core.windows.net"
    timeouts = {"connection_timeout": 10, "read_timeout": 60}
    if account_key:
        return BlobServiceClient(account_url=account_url, credential=account_key, **timeouts)

    # Fall back to DefaultAzureCredential (managed identity / env vars).
    try:
        from azure.identity import DefaultAzureCredential
        credential = DefaultAzureCredential()
        return BlobServiceClient(account_url=account_url, credential=credential, **timeouts)
    except ImportError:
        raise ImportError("azure-identity is required when storage_account_key is not provided")


def _azure_day_partitions(start: datetime, end: datetime) -> list[str]:
    """Date-partition path segments (``/y=…/m=…/d=…/``) covered by the window.

    NSG flow-log blob names embed the full NSG resource ID between
    ``resourceId=`` and the date partition, so the partition can only be
    matched as a substring, not as a name prefix.
    """
    segments: list[str] = []
    day = start.date()
    while day <= end.date():
        segments.append(f"/y={day.year}/m={day.month:02d}/d={day.day:02d}/")
        day += timedelta(days=1)
    return segments


def _azure_tuple_epoch(flow_tuple) -> int | None:
    """Epoch seconds from an NSG flow tuple (first comma-separated field)."""
    try:
        return int(str(flow_tuple).split(",", 1)[0])
    except (ValueError, IndexError):
        return None


def _read_azure_blobs(container_client, start: datetime, end: datetime) -> tuple[list[dict], bool]:
    """Read and parse NSG flow log JSON blobs within the time window.

    Blobs are hourly and appended to in place, so selection is by the date
    partition in the blob name plus ``last_modified``; individual flow tuples
    are then filtered by their embedded epoch timestamp to keep exactly the
    [start, end) window and avoid re-ingesting tuples from earlier pulls.

    Returns ``(records, truncated)``. Errors propagate to the caller so the
    watermark is not advanced past a failed window.
    """
    partitions = _azure_day_partitions(start, end)
    start_epoch = int(start.timestamp())
    end_epoch = int(end.timestamp())
    records: list[dict] = []
    truncated = False

    blobs = container_client.list_blobs(name_starts_with="resourceId=")
    for blob_props in blobs:
        if len(records) >= _MAX_RECORDS_PER_PULL:
            truncated = True
            break
        name = str(blob_props.name or "")
        if not any(seg in name for seg in partitions):
            continue
        last_modified = getattr(blob_props, "last_modified", None)
        if last_modified is not None and last_modified < start:
            continue
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
                    for flow_tuple in flow_set.get("flowTuples", []):
                        epoch = _azure_tuple_epoch(flow_tuple)
                        if epoch is not None and not (start_epoch <= epoch < end_epoch):
                            continue
                        if len(records) >= _MAX_RECORDS_PER_PULL:
                            truncated = True
                            break
                        records.append({
                            "flow_tuples": [flow_tuple],
                            "rule_name": rule_name,
                            "region": str(log_record.get("location") or ""),
                            "resource_id": str(log_record.get("resourceId") or ""),
                        })
    return records, truncated


# ═══════════════════════════════════════════════════════════════════════════
# GCP puller - Cloud Logging export
# ═══════════════════════════════════════════════════════════════════════════

async def pull_gcp_flow_logs(account: dict, *, lookback_minutes: int = _DEFAULT_LOOKBACK_MINUTES) -> dict:
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
    start_dt, end_dt = _window(cursor, lookback_minutes=lookback_minutes)

    total_ingested = 0
    errors: list[str] = []
    warnings: list[str] = []

    try:
        client = _build_gcp_logging_client(auth, project_id)
        records = await _gcp_logging_query(client, project_id, start_dt, end_dt)
        if len(records) >= _MAX_RECORDS_PER_PULL:
            warnings.append(f"results truncated at {_MAX_RECORDS_PER_PULL}")

        if records:
            normalized = _normalize_gcp_flow_records(records)
            if normalized:
                rows = _build_flow_rows_for_ingest(account_id, "gcp", normalized)
                total_ingested = await db.create_flow_records_batch(rows)

        # Advance the watermark only on success so a failed window is
        # retried next cycle instead of silently skipped.
        await _set_cursor(account_id, last_pull_end=end_dt.isoformat())

    except Exception as exc:
        msg = f"GCP flow pull failed: {type(exc).__name__}"
        LOGGER.warning(msg, exc_info=True)
        errors.append(msg)

    return {
        "ok": not errors,
        "partial": False,
        "ingested": total_ingested,
        "errors": errors,
        "warnings": warnings,
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
        except json.JSONDecodeError as exc:
            LOGGER.warning("GCP logging: service_account_json is not valid JSON: %s", exc)
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


async def pull_flow_logs_for_account(account: dict, *, lookback_minutes: int = _DEFAULT_LOOKBACK_MINUTES) -> dict:
    """Pull flow logs for a single cloud account using the correct provider puller."""
    provider = str(account.get("provider") or "").strip().lower()
    puller = _PULLERS.get(provider)
    if not puller:
        return {"ok": False, "error": f"unsupported_provider:{provider}", "ingested": 0}
    async with _account_lock(int(account["id"])):
        return await puller(account, lookback_minutes=lookback_minutes)


async def pull_flow_logs_all_accounts(*, lookback_minutes: int = _DEFAULT_LOOKBACK_MINUTES) -> dict:
    """Iterate all enabled cloud accounts and pull flow logs.

    Returns a summary dict with per-account results.
    """
    accounts = await db.list_cloud_accounts(enabled_only=True)
    eligible: list[dict] = []
    for account in accounts:
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
        eligible.append(account)

    # Bounded concurrency: one hung provider must not stall every other account.
    semaphore = asyncio.Semaphore(_MAX_CONCURRENT_ACCOUNTS)

    async def _pull_one(account: dict) -> tuple[int, dict]:
        account_id = int(account["id"])
        async with semaphore:
            try:
                return account_id, await pull_flow_logs_for_account(
                    account, lookback_minutes=lookback_minutes,
                )
            except Exception as exc:
                LOGGER.warning(
                    "cloud flow pull failed account_id=%s: %s",
                    account_id,
                    type(exc).__name__,
                    exc_info=True,
                )
                return account_id, {"ok": False, "error": str(type(exc).__name__), "ingested": 0}

    gathered = await asyncio.gather(*(_pull_one(account) for account in eligible))
    results: dict[int, dict] = dict(gathered)
    total_ingested = sum(result.get("ingested", 0) for result in results.values())

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
        LOGGER.warning(
            "cloud account %s has no region_scope; defaulting to us-east-1 only",
            account.get("id"),
        )
        return ["us-east-1"]
    return [r.strip() for r in raw.split(",") if r.strip()]
