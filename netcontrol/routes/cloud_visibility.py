"""
cloud_visibility.py -- Cloud network visibility APIs (AWS/Azure/GCP).

Provides:
  - Cloud account CRUD (provider metadata + auth references)
  - Discovery snapshot ingestion (sample/live/auto modes)
    - Cloud traffic-metric ingestion + analytics APIs
  - Cloud resource + connection + hybrid-link APIs for UI topology rendering
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from netcontrol.routes.cloud_collectors import (
    CloudCollectorAuthError,
    CloudCollectorExecutionError,
    CloudCollectorUnavailable,
    collect_provider_snapshot,
    get_provider_capabilities,
)
from netcontrol.routes.shared import _audit, _corr_id, _get_session
from netcontrol.telemetry import configure_logging

router = APIRouter()
LOGGER = configure_logging("plexus.cloud_visibility")

_require_admin = None

_VALID_PROVIDERS = {"aws", "azure", "gcp"}
_VALID_FLOW_INGEST_FORMATS = {"normalized", "aws", "azure", "gcp"}
_VALID_TRAFFIC_INGEST_FORMATS = {"normalized", "aws", "azure", "gcp"}

_FLOW_TYPE_BY_PROVIDER = {
    "aws": "cloud_aws_flow",
    "azure": "cloud_azure_flow",
    "gcp": "cloud_gcp_flow",
}

_PROTOCOL_NUM_BY_NAME = {
    "icmp": 1,
    "tcp": 6,
    "udp": 17,
    "gre": 47,
    "esp": 50,
    "ah": 51,
    "ospf": 89,
    "sctp": 132,
}

_PROVIDER_INFO = {
    "aws": {
        "name": "Amazon Web Services",
        "focus_constructs": ["VPC", "Transit Gateway", "Direct Connect", "Security Groups"],
    },
    "azure": {
        "name": "Microsoft Azure",
        "focus_constructs": ["VNet", "VNet Peering", "ExpressRoute", "NSG"],
    },
    "gcp": {
        "name": "Google Cloud Platform",
        "focus_constructs": ["VPC", "Cloud Router", "HA VPN", "Firewall Policies"],
    },
}


def init_cloud_visibility(require_admin):
    global _require_admin
    _require_admin = require_admin


async def _require_admin_dep(request: Request):
    if _require_admin is None:
        raise HTTPException(status_code=500, detail="Authorization subsystem not initialized")
    return await _require_admin(request)


def _normalize_provider(raw: str | None) -> str:
    provider = str(raw or "").strip().lower()
    if provider not in _VALID_PROVIDERS:
        raise ValueError("invalid_provider")
    return provider


def _json_loads_safe(raw: str | None, fallback):
    if not raw:
        return fallback
    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return fallback


def _collect_sync_errors(result: dict) -> list[str]:
    errors: list[str] = []
    direct_errors = result.get("errors")
    if isinstance(direct_errors, list):
        errors.extend(str(item).strip() for item in direct_errors if str(item).strip())

    nested = result.get("results")
    if isinstance(nested, dict):
        for item in nested.values():
            if not isinstance(item, dict):
                continue
            nested_errors = item.get("errors")
            if isinstance(nested_errors, list):
                errors.extend(str(err).strip() for err in nested_errors if str(err).strip())
            nested_error = str(item.get("error") or "").strip()
            if nested_error:
                errors.append(nested_error)

    return errors[:50]


def build_cloud_sync_status(
    result: dict,
    *,
    source: str,
    scope: str,
    account_id: int | None = None,
    account_name: str = "",
) -> dict:
    import netcontrol.routes.state as state

    ingested = int(result.get("ingested", result.get("total_ingested", 0)) or 0)
    accounts_processed = int(result.get("accounts_processed", 1 if scope == "account" else 0) or 0)
    errors = _collect_sync_errors(result)
    ok_value = result.get("ok")
    if isinstance(ok_value, bool):
        ok = ok_value
    else:
        ok = len(errors) == 0

    return state._sanitize_cloud_sync_status(
        {
            "last_run_at": datetime.now(UTC).isoformat(),
            "source": source,
            "scope": scope,
            "account_id": account_id,
            "account_name": account_name,
            "ok": ok,
            "ingested": ingested,
            "accounts_processed": accounts_processed,
            "error_count": len(errors),
            "errors": errors,
        }
    )


async def persist_cloud_flow_sync_status(status: dict) -> dict:
    import netcontrol.routes.state as state

    sanitized = state._sanitize_cloud_sync_status(status)
    state.CLOUD_FLOW_SYNC_STATUS = sanitized
    await db.set_auth_setting("cloud_flow_sync_status", sanitized)
    return sanitized


async def persist_cloud_traffic_sync_status(status: dict) -> dict:
    import netcontrol.routes.state as state

    sanitized = state._sanitize_cloud_sync_status(status)
    state.CLOUD_TRAFFIC_METRIC_SYNC_STATUS = sanitized
    await db.set_auth_setting("cloud_traffic_metric_sync_status", sanitized)
    return sanitized


def _serialize_account(account: dict) -> dict:
    item = dict(account)
    item["auth_config"] = _json_loads_safe(item.get("auth_config_json"), {})
    return item


def _serialize_resource(resource: dict) -> dict:
    item = dict(resource)
    item["metadata"] = _json_loads_safe(item.get("metadata_json"), {})
    return item


def _serialize_connection(connection: dict) -> dict:
    item = dict(connection)
    item["metadata"] = _json_loads_safe(item.get("metadata_json"), {})
    return item


def _serialize_hybrid_link(link: dict) -> dict:
    item = dict(link)
    item["metadata"] = _json_loads_safe(item.get("metadata_json"), {})
    return item


def _serialize_policy_rule(rule: dict) -> dict:
    item = dict(rule)
    item["metadata"] = _json_loads_safe(item.get("metadata_json"), {})
    return item


class CloudAccountCreate(BaseModel):
    provider: str
    name: str = Field(min_length=1)
    account_identifier: str = ""
    region_scope: str = ""
    auth_type: str = "manual"
    auth_config: dict = Field(default_factory=dict)
    notes: str = ""
    enabled: bool = True


class CloudAccountUpdate(BaseModel):
    provider: str | None = None
    name: str | None = None
    account_identifier: str | None = None
    region_scope: str | None = None
    auth_type: str | None = None
    auth_config: dict | None = None
    notes: str | None = None
    enabled: bool | None = None


class CloudDiscoveryRequest(BaseModel):
    mode: str = "auto"  # sample | live | auto
    connect_host_ids: list[int] = Field(default_factory=list)
    include_hybrid_links: bool = True


class CloudValidationRequest(BaseModel):
    mode: str = "live"  # live | sample


class CloudFlowIngestRequest(BaseModel):
    format: str = "normalized"  # normalized | aws | azure | gcp
    records: list[dict] = Field(default_factory=list)
    source: str = "api"
    emit_event: bool = True


class CloudTrafficMetricIngestRequest(BaseModel):
    format: str = "normalized"  # normalized | aws | azure | gcp
    records: list[dict] = Field(default_factory=list)
    source: str = "api"
    emit_event: bool = True


def _safe_float(value, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        if isinstance(value, bool):
            return float(int(value))
        if isinstance(value, (int, float)):
            return float(value)
        text = str(value).strip()
        if not text:
            return default
        return float(text)
    except Exception:
        return default


def _safe_int(value, default: int = 0) -> int:
    try:
        if value is None:
            return default
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, (int, float)):
            return int(value)
        text = str(value).strip()
        if not text:
            return default
        if text.isdigit():
            return int(text)
        return int(float(text))
    except Exception:
        return default


def _normalize_protocol(value) -> int:
    parsed = _safe_int(value, -1)
    if parsed >= 0:
        return parsed
    lowered = str(value or "").strip().lower()
    return _PROTOCOL_NUM_BY_NAME.get(lowered, 0)


def _normalize_timestamp_iso(value) -> str:
    if value is None:
        return datetime.now(UTC).isoformat()
    if isinstance(value, (int, float)):
        ts = float(value)
        if ts > 1_000_000_000_000:
            ts = ts / 1000.0
        try:
            return datetime.fromtimestamp(ts, tz=UTC).isoformat()
        except Exception:
            return datetime.now(UTC).isoformat()
    raw = str(value).strip()
    if not raw:
        return datetime.now(UTC).isoformat()
    if raw.isdigit():
        return _normalize_timestamp_iso(int(raw))
    normalized = raw.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC).isoformat()
    except Exception:
        return datetime.now(UTC).isoformat()


def _normalize_generic_flow_records(records: list[dict]) -> list[dict]:
    normalized: list[dict] = []
    for item in records:
        if not isinstance(item, dict):
            continue
        src_ip = str(
            item.get("src_ip")
            or item.get("srcaddr")
            or item.get("source_ip")
            or item.get("srcIp")
            or ""
        ).strip()
        dst_ip = str(
            item.get("dst_ip")
            or item.get("dstaddr")
            or item.get("destination_ip")
            or item.get("dstIp")
            or item.get("dest_ip")
            or ""
        ).strip()
        if not src_ip or not dst_ip:
            continue
        start_time = _normalize_timestamp_iso(item.get("start_time") or item.get("start") or item.get("timestamp"))
        end_time = _normalize_timestamp_iso(item.get("end_time") or item.get("end") or start_time)
        normalized.append(
            {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": _safe_int(item.get("src_port") or item.get("srcport")),
                "dst_port": _safe_int(item.get("dst_port") or item.get("dstport")),
                "protocol": _normalize_protocol(item.get("protocol")),
                "bytes": _safe_int(item.get("bytes") or item.get("octets")),
                "packets": _safe_int(item.get("packets") or item.get("in_pkts")),
                "start_time": start_time,
                "end_time": end_time,
                "action": str(item.get("action") or "").strip().lower(),
                "direction": str(item.get("direction") or "").strip().lower(),
                "region": str(item.get("region") or "").strip(),
                "vpc_id": str(item.get("vpc_id") or item.get("vpc-id") or "").strip(),
                "subnet_id": str(item.get("subnet_id") or item.get("subnet-id") or "").strip(),
                "metadata": item.get("metadata") if isinstance(item.get("metadata"), dict) else {},
            }
        )
    return normalized


def _normalize_aws_flow_records(records: list[dict]) -> list[dict]:
    normalized: list[dict] = []
    for item in records:
        if not isinstance(item, dict):
            continue
        src_ip = str(item.get("srcaddr") or item.get("srcAddr") or "").strip()
        dst_ip = str(item.get("dstaddr") or item.get("dstAddr") or "").strip()
        if not src_ip or not dst_ip:
            normalized.extend(_normalize_generic_flow_records([item]))
            continue
        start_time = _normalize_timestamp_iso(item.get("start"))
        end_time = _normalize_timestamp_iso(item.get("end") or start_time)
        normalized.append(
            {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": _safe_int(item.get("srcport")),
                "dst_port": _safe_int(item.get("dstport")),
                "protocol": _normalize_protocol(item.get("protocol")),
                "bytes": _safe_int(item.get("bytes")),
                "packets": _safe_int(item.get("packets")),
                "start_time": start_time,
                "end_time": end_time,
                "action": str(item.get("action") or "").strip().lower(),
                "direction": str(item.get("flow-direction") or item.get("direction") or "").strip().lower(),
                "region": str(item.get("region") or "").strip(),
                "vpc_id": str(item.get("vpc-id") or item.get("vpc_id") or "").strip(),
                "subnet_id": str(item.get("subnet-id") or item.get("subnet_id") or "").strip(),
                "metadata": {
                    "interface_id": str(item.get("interface-id") or item.get("interface_id") or "").strip(),
                    "log_status": str(item.get("log-status") or item.get("log_status") or "").strip(),
                },
            }
        )
    return normalized


def _normalize_azure_flow_records(records: list[dict]) -> list[dict]:
    normalized: list[dict] = []
    for item in records:
        if not isinstance(item, dict):
            continue
        flow_tuples = item.get("flow_tuples") or item.get("flowTuples") or []
        if isinstance(flow_tuples, list) and flow_tuples:
            for tuple_item in flow_tuples:
                parts = [str(p).strip() for p in str(tuple_item or "").split(",")]
                if len(parts) < 6:
                    continue
                src_ip = parts[1] if len(parts) > 1 else ""
                dst_ip = parts[2] if len(parts) > 2 else ""
                if not src_ip or not dst_ip:
                    continue
                normalized.append(
                    {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": _safe_int(parts[3] if len(parts) > 3 else 0),
                        "dst_port": _safe_int(parts[4] if len(parts) > 4 else 0),
                        "protocol": _normalize_protocol(parts[5] if len(parts) > 5 else 0),
                        "bytes": _safe_int(parts[9] if len(parts) > 9 else item.get("bytes")),
                        "packets": _safe_int(parts[8] if len(parts) > 8 else item.get("packets")),
                        "start_time": _normalize_timestamp_iso(parts[0] if len(parts) > 0 else item.get("start_time")),
                        "end_time": _normalize_timestamp_iso(item.get("end_time") or parts[0] if len(parts) > 0 else None),
                        "action": str(parts[7] if len(parts) > 7 else item.get("action") or "").strip().lower(),
                        "direction": str(parts[6] if len(parts) > 6 else item.get("direction") or "").strip().lower(),
                        "region": str(item.get("region") or item.get("location") or "").strip(),
                        "vpc_id": str(item.get("vnet_id") or item.get("vnetId") or "").strip(),
                        "subnet_id": str(item.get("subnet_id") or item.get("subnetId") or "").strip(),
                        "metadata": {
                            "resource_id": str(item.get("resource_id") or item.get("resourceId") or "").strip(),
                            "rule_name": str(item.get("rule_name") or item.get("ruleName") or "").strip(),
                        },
                    }
                )
            continue
        normalized.extend(_normalize_generic_flow_records([item]))
    return normalized


def _normalize_gcp_flow_records(records: list[dict]) -> list[dict]:
    normalized: list[dict] = []
    for item in records:
        if not isinstance(item, dict):
            continue
        conn = item.get("connection") if isinstance(item.get("connection"), dict) else {}
        src_ip = str(
            item.get("src_ip")
            or item.get("srcIp")
            or conn.get("src_ip")
            or conn.get("srcIp")
            or ""
        ).strip()
        dst_ip = str(
            item.get("dst_ip")
            or item.get("dest_ip")
            or item.get("destIp")
            or conn.get("dest_ip")
            or conn.get("destIp")
            or ""
        ).strip()
        if not src_ip or not dst_ip:
            continue
        bytes_total = _safe_int(item.get("bytes"))
        if bytes_total <= 0:
            bytes_total = _safe_int(item.get("bytes_sent")) + _safe_int(item.get("bytes_received"))
        packets_total = _safe_int(item.get("packets"))
        if packets_total <= 0:
            packets_total = _safe_int(item.get("packets_sent")) + _safe_int(item.get("packets_received"))
        start_time = _normalize_timestamp_iso(item.get("start_time") or item.get("start"))
        end_time = _normalize_timestamp_iso(item.get("end_time") or item.get("end") or start_time)
        normalized.append(
            {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": _safe_int(item.get("src_port") or conn.get("src_port")),
                "dst_port": _safe_int(item.get("dst_port") or item.get("dest_port") or conn.get("dest_port")),
                "protocol": _normalize_protocol(item.get("protocol") or conn.get("protocol")),
                "bytes": bytes_total,
                "packets": packets_total,
                "start_time": start_time,
                "end_time": end_time,
                "action": str(item.get("disposition") or item.get("action") or "").strip().lower(),
                "direction": str(item.get("direction") or item.get("reporter") or "").strip().lower(),
                "region": str(item.get("region") or item.get("location") or "").strip(),
                "vpc_id": str(item.get("vpc_id") or item.get("network") or "").strip(),
                "subnet_id": str(item.get("subnetwork") or item.get("subnet_id") or "").strip(),
                "metadata": {
                    "instance": str(item.get("instance") or "").strip(),
                    "project_id": str(item.get("project_id") or item.get("projectId") or "").strip(),
                },
            }
        )
    return normalized


def _prepare_flow_ingest_records(provider: str, flow_format: str, records: list[dict]) -> list[dict]:
    normalized_provider = _normalize_provider(provider)
    mode = str(flow_format or "normalized").strip().lower()
    if mode not in _VALID_FLOW_INGEST_FORMATS:
        raise ValueError("unsupported_flow_format")
    if mode != "normalized" and mode != normalized_provider:
        raise ValueError("mismatched_flow_format_provider")
    if mode == "normalized":
        return _normalize_generic_flow_records(records)
    if mode == "aws":
        return _normalize_aws_flow_records(records)
    if mode == "azure":
        return _normalize_azure_flow_records(records)
    return _normalize_gcp_flow_records(records)


def _build_flow_rows_for_ingest(account_id: int, provider: str, records: list[dict]) -> list[tuple]:
    exporter_ip = f"cloud-account-{int(account_id)}"
    flow_type = _FLOW_TYPE_BY_PROVIDER[provider]
    rows: list[tuple] = []
    for record in records:
        rows.append(
            (
                exporter_ip,
                None,
                flow_type,
                str(record.get("src_ip") or ""),
                str(record.get("dst_ip") or ""),
                _safe_int(record.get("src_port")),
                _safe_int(record.get("dst_port")),
                _safe_int(record.get("protocol")),
                _safe_int(record.get("bytes")),
                _safe_int(record.get("packets")),
                0,
                0,
                0,
                0,
                0,
                0,
                _normalize_timestamp_iso(record.get("start_time")),
                _normalize_timestamp_iso(record.get("end_time")),
            )
        )
    return rows


def _summarize_flow_records(records: list[dict]) -> dict:
    unique_sources = set()
    unique_destinations = set()
    actions: dict[str, int] = {}
    directions: dict[str, int] = {}
    total_bytes = 0
    total_packets = 0
    timestamps: list[str] = []

    for record in records:
        src_ip = str(record.get("src_ip") or "").strip()
        dst_ip = str(record.get("dst_ip") or "").strip()
        if src_ip:
            unique_sources.add(src_ip)
        if dst_ip:
            unique_destinations.add(dst_ip)
        total_bytes += _safe_int(record.get("bytes"))
        total_packets += _safe_int(record.get("packets"))
        action = str(record.get("action") or "").strip().lower()
        if action:
            actions[action] = actions.get(action, 0) + 1
        direction = str(record.get("direction") or "").strip().lower()
        if direction:
            directions[direction] = directions.get(direction, 0) + 1
        start_time = str(record.get("start_time") or "").strip()
        end_time = str(record.get("end_time") or "").strip()
        if start_time:
            timestamps.append(start_time)
        if end_time:
            timestamps.append(end_time)

    return {
        "flow_count": len(records),
        "total_bytes": total_bytes,
        "total_packets": total_packets,
        "unique_sources": len(unique_sources),
        "unique_destinations": len(unique_destinations),
        "first_ts": min(timestamps) if timestamps else None,
        "last_ts": max(timestamps) if timestamps else None,
        "action_breakdown": actions,
        "direction_breakdown": directions,
    }


def _extract_resource_uid_from_dimensions(dimensions) -> str:
    if not isinstance(dimensions, list):
        return ""
    preferred_keys = {
        "vpcid",
        "subnetid",
        "instanceid",
        "transitgatewayid",
        "networkinterfaceid",
        "loadbalancer",
        "natgatewayid",
        "resourceid",
    }
    first_fallback = ""
    for item in dimensions:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("Name") or "").strip()
        value = str(item.get("value") or item.get("Value") or "").strip()
        if not value:
            continue
        if not first_fallback:
            first_fallback = value
        if name.lower() in preferred_keys:
            return value
    return first_fallback


def _normalize_generic_traffic_metric_records(records: list[dict]) -> list[dict]:
    normalized: list[dict] = []
    for item in records:
        if not isinstance(item, dict):
            continue
        metric_name = str(
            item.get("metric_name")
            or item.get("metricName")
            or item.get("name")
            or ""
        ).strip()
        if not metric_name:
            continue
        interval_start = _normalize_timestamp_iso(
            item.get("interval_start")
            or item.get("start_time")
            or item.get("start")
            or item.get("timestamp")
            or item.get("time")
        )
        interval_end = _normalize_timestamp_iso(
            item.get("interval_end")
            or item.get("end_time")
            or item.get("end")
            or item.get("timestamp")
            or item.get("time")
            or interval_start
        )
        value = _safe_float(item.get("value"), None)
        if value is None:
            for alt in ("sum", "total", "average", "avg", "maximum", "max", "minimum", "min"):
                value = _safe_float(item.get(alt), None)
                if value is not None:
                    break
        if value is None:
            continue

        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        normalized.append(
            {
                "metric_name": metric_name,
                "metric_namespace": str(item.get("metric_namespace") or item.get("namespace") or "").strip(),
                "resource_uid": str(
                    item.get("resource_uid")
                    or item.get("resource_id")
                    or item.get("resourceId")
                    or item.get("resource")
                    or ""
                ).strip(),
                "direction": str(item.get("direction") or "").strip().lower(),
                "statistic": str(item.get("statistic") or item.get("aggregation") or "").strip().lower(),
                "unit": str(item.get("unit") or "").strip(),
                "value": value,
                "interval_start": interval_start,
                "interval_end": interval_end,
                "metadata": metadata,
            }
        )
    return normalized


def _normalize_aws_traffic_metric_records(records: list[dict]) -> list[dict]:
    normalized: list[dict] = []
    for item in records:
        if not isinstance(item, dict):
            continue
        metric_name = str(item.get("MetricName") or item.get("metric_name") or "").strip()
        if not metric_name:
            normalized.extend(_normalize_generic_traffic_metric_records([item]))
            continue
        timestamp = _normalize_timestamp_iso(item.get("Timestamp") or item.get("timestamp"))
        value = _safe_float(item.get("Value"), None)
        if value is None:
            for alt in ("Sum", "Average", "Maximum", "Minimum", "SampleCount"):
                value = _safe_float(item.get(alt), None)
                if value is not None:
                    break
        if value is None:
            continue
        dimensions = item.get("Dimensions")
        metadata = {
            "dimensions": dimensions if isinstance(dimensions, list) else [],
        }
        normalized.append(
            {
                "metric_name": metric_name,
                "metric_namespace": str(item.get("Namespace") or item.get("namespace") or "").strip(),
                "resource_uid": _extract_resource_uid_from_dimensions(dimensions),
                "direction": str(item.get("direction") or "").strip().lower(),
                "statistic": str(item.get("Statistic") or item.get("statistic") or "").strip().lower(),
                "unit": str(item.get("Unit") or item.get("unit") or "").strip(),
                "value": value,
                "interval_start": timestamp,
                "interval_end": timestamp,
                "metadata": metadata,
            }
        )
    return normalized


def _normalize_azure_traffic_metric_records(records: list[dict]) -> list[dict]:
    normalized: list[dict] = []
    for item in records:
        if not isinstance(item, dict):
            continue
        metric_name_raw = item.get("metricName")
        if isinstance(metric_name_raw, dict):
            metric_name = str(metric_name_raw.get("value") or metric_name_raw.get("localizedValue") or "").strip()
        else:
            metric_name = str(metric_name_raw or item.get("metric_name") or "").strip()
        if not metric_name:
            normalized.extend(_normalize_generic_traffic_metric_records([item]))
            continue
        value = None
        statistic = ""
        for alt_name, alt_stat in (("total", "total"), ("average", "avg"), ("maximum", "max"), ("minimum", "min")):
            alt = _safe_float(item.get(alt_name), None)
            if alt is not None:
                value = alt
                statistic = alt_stat
                break
        if value is None:
            value = _safe_float(item.get("value"), None)
        if value is None:
            continue
        timestamp = _normalize_timestamp_iso(item.get("timeStamp") or item.get("timestamp"))
        normalized.append(
            {
                "metric_name": metric_name,
                "metric_namespace": str(item.get("namespace") or "azure.monitor").strip(),
                "resource_uid": str(item.get("resourceId") or item.get("resource_id") or "").strip(),
                "direction": str(item.get("direction") or "").strip().lower(),
                "statistic": str(item.get("statistic") or statistic).strip().lower(),
                "unit": str(item.get("unit") or "").strip(),
                "value": value,
                "interval_start": timestamp,
                "interval_end": timestamp,
                "metadata": item.get("metadata") if isinstance(item.get("metadata"), dict) else {},
            }
        )
    return normalized


def _normalize_gcp_traffic_metric_records(records: list[dict]) -> list[dict]:
    normalized: list[dict] = []
    for item in records:
        if not isinstance(item, dict):
            continue
        metric = item.get("metric") if isinstance(item.get("metric"), dict) else {}
        resource = item.get("resource") if isinstance(item.get("resource"), dict) else {}
        points = item.get("points") if isinstance(item.get("points"), list) else []
        metric_name = str(item.get("metric_name") or item.get("metricType") or metric.get("type") or "").strip()
        if not metric_name:
            normalized.extend(_normalize_generic_traffic_metric_records([item]))
            continue
        resource_labels = resource.get("labels") if isinstance(resource.get("labels"), dict) else {}
        resource_uid = str(
            resource_labels.get("instance_id")
            or resource_labels.get("subnetwork_name")
            or resource_labels.get("network_name")
            or item.get("resource_id")
            or ""
        ).strip()
        if not points:
            value = _safe_float(item.get("value"), None)
            if value is None:
                continue
            ts = _normalize_timestamp_iso(item.get("timestamp") or item.get("time"))
            normalized.append(
                {
                    "metric_name": metric_name,
                    "metric_namespace": str(item.get("metric_namespace") or "gcp.monitoring").strip(),
                    "resource_uid": resource_uid,
                    "direction": str(item.get("direction") or "").strip().lower(),
                    "statistic": str(item.get("statistic") or "").strip().lower(),
                    "unit": str(item.get("unit") or "").strip(),
                    "value": value,
                    "interval_start": ts,
                    "interval_end": ts,
                    "metadata": item.get("metadata") if isinstance(item.get("metadata"), dict) else {},
                }
            )
            continue
        for point in points:
            if not isinstance(point, dict):
                continue
            interval = point.get("interval") if isinstance(point.get("interval"), dict) else {}
            value_obj = point.get("value") if isinstance(point.get("value"), dict) else {}
            value = None
            for key in ("doubleValue", "int64Value", "distributionValue"):
                if key == "distributionValue":
                    dist = value_obj.get(key)
                    if isinstance(dist, dict):
                        value = _safe_float(dist.get("mean"), None)
                else:
                    value = _safe_float(value_obj.get(key), None)
                if value is not None:
                    break
            if value is None:
                continue
            normalized.append(
                {
                    "metric_name": metric_name,
                    "metric_namespace": str(item.get("metric_namespace") or "gcp.monitoring").strip(),
                    "resource_uid": resource_uid,
                    "direction": str(item.get("direction") or "").strip().lower(),
                    "statistic": str(item.get("statistic") or "").strip().lower(),
                    "unit": str(item.get("unit") or "").strip(),
                    "value": value,
                    "interval_start": _normalize_timestamp_iso(interval.get("startTime") or point.get("startTime")),
                    "interval_end": _normalize_timestamp_iso(interval.get("endTime") or point.get("endTime")),
                    "metadata": {
                        "metric_labels": metric.get("labels") if isinstance(metric.get("labels"), dict) else {},
                        "resource_labels": resource_labels,
                    },
                }
            )
    return normalized


def _prepare_traffic_metric_ingest_records(provider: str, ingest_format: str, records: list[dict]) -> list[dict]:
    normalized_provider = _normalize_provider(provider)
    mode = str(ingest_format or "normalized").strip().lower()
    if mode not in _VALID_TRAFFIC_INGEST_FORMATS:
        raise ValueError("unsupported_traffic_format")
    if mode != "normalized" and mode != normalized_provider:
        raise ValueError("mismatched_traffic_format_provider")
    if mode == "normalized":
        return _normalize_generic_traffic_metric_records(records)
    if mode == "aws":
        return _normalize_aws_traffic_metric_records(records)
    if mode == "azure":
        return _normalize_azure_traffic_metric_records(records)
    return _normalize_gcp_traffic_metric_records(records)


def _build_traffic_metric_rows_for_ingest(
    account_id: int,
    provider: str,
    records: list[dict],
    *,
    source: str,
) -> list[tuple]:
    rows: list[tuple] = []
    for record in records:
        rows.append(
            (
                int(account_id),
                provider,
                str(record.get("metric_name") or "").strip(),
                str(record.get("metric_namespace") or "").strip(),
                str(record.get("resource_uid") or "").strip(),
                str(record.get("direction") or "").strip().lower(),
                str(record.get("statistic") or "").strip().lower(),
                str(record.get("unit") or "").strip(),
                _safe_float(record.get("value")),
                _normalize_timestamp_iso(record.get("interval_start")),
                _normalize_timestamp_iso(record.get("interval_end")),
                json.dumps(record.get("metadata") or {})[:2000],
                source,
            )
        )
    return rows


def _summarize_traffic_metric_records(records: list[dict]) -> dict:
    metric_names = set()
    resource_uids = set()
    values: list[float] = []
    timestamps: list[str] = []
    for record in records:
        metric_name = str(record.get("metric_name") or "").strip()
        resource_uid = str(record.get("resource_uid") or "").strip()
        if metric_name:
            metric_names.add(metric_name)
        if resource_uid:
            resource_uids.add(resource_uid)
        value = _safe_float(record.get("value"), None)
        if value is not None:
            values.append(value)
        start_time = str(record.get("interval_start") or "").strip()
        end_time = str(record.get("interval_end") or "").strip()
        if start_time:
            timestamps.append(start_time)
        if end_time:
            timestamps.append(end_time)

    total = sum(values) if values else 0.0
    return {
        "sample_count": len(records),
        "metric_count": len(metric_names),
        "resource_count": len(resource_uids),
        "total_value": total,
        "avg_value": (total / len(values)) if values else 0.0,
        "min_value": min(values) if values else 0.0,
        "max_value": max(values) if values else 0.0,
        "first_ts": min(timestamps) if timestamps else None,
        "last_ts": max(timestamps) if timestamps else None,
    }


def _sample_snapshot_for_provider(provider: str) -> tuple[list[dict], list[dict]]:
    if provider == "aws":
        resources = [
            {"resource_uid": "aws:vpc:core", "resource_type": "vpc", "name": "prod-core-vpc", "region": "us-east-1", "cidr": "10.200.0.0/16", "status": "active"},
            {"resource_uid": "aws:tgw:global", "resource_type": "transit_gateway", "name": "global-tgw", "region": "us-east-1", "status": "active"},
            {"resource_uid": "aws:dx:primary", "resource_type": "direct_connect", "name": "dx-primary", "region": "us-east-1", "status": "up"},
            {"resource_uid": "aws:internet_gateway:igw-core", "resource_type": "internet_gateway", "name": "igw-core", "region": "us-east-1", "status": "attached"},
            {"resource_uid": "aws:nat_gateway:nat-core-a", "resource_type": "nat_gateway", "name": "nat-core-a", "region": "us-east-1", "status": "available"},
            {"resource_uid": "aws:route_table:rtb-core", "resource_type": "route_table", "name": "rtb-core", "region": "us-east-1", "status": "active", "metadata": {"route_count": 3, "association_count": 2}},
            {
                "resource_uid": "aws:sg:app-edge",
                "resource_type": "security_group",
                "name": "sg-app-edge",
                "region": "us-east-1",
                "status": "active",
                "metadata": {
                    "policy_rules": [
                        {
                            "rule_uid": "aws:sg:app-edge:ingress:https",
                            "rule_name": "HTTPS ingress",
                            "direction": "inbound",
                            "action": "allow",
                            "protocol": "tcp",
                            "source_selector": "0.0.0.0/0",
                            "destination_selector": "self",
                            "port_expression": "443",
                        },
                        {
                            "rule_uid": "aws:sg:app-edge:egress:any",
                            "rule_name": "All egress",
                            "direction": "outbound",
                            "action": "allow",
                            "protocol": "all",
                            "source_selector": "self",
                            "destination_selector": "0.0.0.0/0",
                            "port_expression": "all",
                        },
                    ],
                },
            },
        ]
        connections = [
            {"source_resource_uid": "aws:vpc:core", "target_resource_uid": "aws:tgw:global", "connection_type": "transit_gateway_attachment", "state": "attached"},
            {"source_resource_uid": "aws:tgw:global", "target_resource_uid": "aws:dx:primary", "connection_type": "direct_connect_gateway", "state": "up"},
            {"source_resource_uid": "aws:vpc:core", "target_resource_uid": "aws:internet_gateway:igw-core", "connection_type": "internet_gateway_attachment", "state": "attached"},
            {"source_resource_uid": "aws:vpc:core", "target_resource_uid": "aws:route_table:rtb-core", "connection_type": "route_table_association", "state": "attached"},
            {"source_resource_uid": "aws:route_table:rtb-core", "target_resource_uid": "aws:nat_gateway:nat-core-a", "connection_type": "route_next_hop", "state": "active", "metadata": {"destination": "0.0.0.0/0"}},
            {"source_resource_uid": "aws:vpc:core", "target_resource_uid": "aws:sg:app-edge", "connection_type": "security_boundary", "state": "enforced"},
        ]
        return resources, connections

    if provider == "azure":
        resources = [
            {"resource_uid": "azure:vnet:core", "resource_type": "vnet", "name": "corp-core-vnet", "region": "centralus", "cidr": "10.210.0.0/16", "status": "connected"},
            {"resource_uid": "azure:vnet:shared", "resource_type": "vnet", "name": "shared-services-vnet", "region": "centralus", "cidr": "10.211.0.0/16", "status": "connected"},
            {"resource_uid": "azure:er:primary", "resource_type": "expressroute", "name": "er-primary", "region": "centralus", "status": "provisioned"},
            {"resource_uid": "azure:virtual_network_gateway:core", "resource_type": "virtual_network_gateway", "name": "vgw-core", "region": "centralus", "status": "active", "metadata": {"gateway_type": "Vpn"}},
            {"resource_uid": "azure:local_network_gateway:hq", "resource_type": "local_network_gateway", "name": "lng-hq", "region": "centralus", "status": "active"},
            {"resource_uid": "azure:route_table:core", "resource_type": "route_table", "name": "rt-core", "region": "centralus", "status": "active", "metadata": {"route_count": 2}},
            {
                "resource_uid": "azure:nsg:edge",
                "resource_type": "network_security_group",
                "name": "nsg-edge",
                "region": "centralus",
                "status": "active",
                "metadata": {
                    "policy_rules": [
                        {
                            "rule_uid": "azure:nsg:edge:allow-web",
                            "rule_name": "AllowWeb",
                            "direction": "inbound",
                            "action": "allow",
                            "protocol": "tcp",
                            "source_selector": "10.0.0.0/8",
                            "destination_selector": "10.210.10.0/24",
                            "port_expression": "80,443",
                            "priority": 100,
                        },
                        {
                            "rule_uid": "azure:nsg:edge:deny-internet",
                            "rule_name": "DenyInternet",
                            "direction": "outbound",
                            "action": "deny",
                            "protocol": "all",
                            "source_selector": "10.210.10.0/24",
                            "destination_selector": "Internet",
                            "port_expression": "all",
                            "priority": 4096,
                        },
                    ],
                },
            },
        ]
        connections = [
            {"source_resource_uid": "azure:vnet:core", "target_resource_uid": "azure:vnet:shared", "connection_type": "vnet_peering", "state": "connected"},
            {"source_resource_uid": "azure:vnet:core", "target_resource_uid": "azure:er:primary", "connection_type": "expressroute_gateway", "state": "up"},
            {"source_resource_uid": "azure:vnet:core", "target_resource_uid": "azure:virtual_network_gateway:core", "connection_type": "virtual_network_gateway_attachment", "state": "attached"},
            {"source_resource_uid": "azure:virtual_network_gateway:core", "target_resource_uid": "azure:local_network_gateway:hq", "connection_type": "ipsec", "state": "connected"},
            {"source_resource_uid": "azure:vnet:core", "target_resource_uid": "azure:route_table:core", "connection_type": "route_table_association", "state": "attached", "metadata": {"subnet_name": "GatewaySubnet"}},
            {"source_resource_uid": "azure:vnet:core", "target_resource_uid": "azure:nsg:edge", "connection_type": "security_boundary", "state": "enforced"},
        ]
        return resources, connections

    resources = [
        {"resource_uid": "gcp:vpc:core", "resource_type": "vpc", "name": "gcp-core-vpc", "region": "us-central1", "cidr": "10.220.0.0/16", "status": "active"},
        {"resource_uid": "gcp:vpc:shared", "resource_type": "vpc", "name": "gcp-shared-vpc", "region": "us-central1", "cidr": "10.221.0.0/16", "status": "active"},
        {"resource_uid": "gcp:router:core", "resource_type": "cloud_router", "name": "cr-core", "region": "us-central1", "status": "running"},
        {"resource_uid": "gcp:vpn:ha", "resource_type": "ha_vpn_gateway", "name": "ha-vpn-gw", "region": "us-central1", "status": "up"},
        {"resource_uid": "gcp:interconnect_attachment:core", "resource_type": "interconnect_attachment", "name": "ia-core", "region": "us-central1", "status": "AVAILABLE"},
        {"resource_uid": "gcp:route:default-egress", "resource_type": "route_entry", "name": "default-egress", "region": "global", "cidr": "0.0.0.0/0", "status": "active", "metadata": {"next_hop": "default-internet-gateway", "priority": 1000}},
        {
            "resource_uid": "gcp:fw:edge",
            "resource_type": "firewall_policy",
            "name": "fw-edge-policy",
            "region": "global",
            "status": "active",
            "metadata": {
                "policy_rules": [
                    {
                        "rule_uid": "gcp:fw:edge:allow-https",
                        "rule_name": "allow-https",
                        "direction": "inbound",
                        "action": "allow",
                        "protocol": "tcp",
                        "source_selector": "35.191.0.0/16, 130.211.0.0/22",
                        "destination_selector": "self",
                        "port_expression": "443",
                        "priority": 1000,
                    },
                    {
                        "rule_uid": "gcp:fw:edge:deny-ssh",
                        "rule_name": "deny-ssh",
                        "direction": "inbound",
                        "action": "deny",
                        "protocol": "tcp",
                        "source_selector": "0.0.0.0/0",
                        "destination_selector": "self",
                        "port_expression": "22",
                        "priority": 1100,
                    },
                ],
            },
        },
    ]
    connections = [
        {"source_resource_uid": "gcp:vpc:core", "target_resource_uid": "gcp:router:core", "connection_type": "router_attachment", "state": "up"},
        {"source_resource_uid": "gcp:router:core", "target_resource_uid": "gcp:vpn:ha", "connection_type": "vpn_tunnel", "state": "up"},
        {"source_resource_uid": "gcp:vpc:core", "target_resource_uid": "gcp:vpc:shared", "connection_type": "vpc_peering", "state": "ACTIVE"},
        {"source_resource_uid": "gcp:router:core", "target_resource_uid": "gcp:interconnect_attachment:core", "connection_type": "interconnect_attachment", "state": "AVAILABLE"},
        {"source_resource_uid": "gcp:vpc:core", "target_resource_uid": "gcp:route:default-egress", "connection_type": "route_table_association", "state": "active"},
        {"source_resource_uid": "gcp:vpc:core", "target_resource_uid": "gcp:fw:edge", "connection_type": "security_boundary", "state": "enforced"},
    ]
    return resources, connections


async def _resolve_hybrid_hosts(connect_host_ids: list[int]) -> list[dict]:
    hosts = []
    if connect_host_ids:
        valid_ids: list[int] = []
        for host_id in connect_host_ids:
            try:
                parsed = int(host_id)
            except Exception:
                continue
            if parsed > 0:
                valid_ids.append(parsed)
        if valid_ids:
            hosts = await db.get_hosts_by_ids(valid_ids)
    if not hosts:
        hosts = (await db.get_all_hosts())[:2]
    return hosts


def _pick_hybrid_entry(provider: str, resources: list[dict]) -> tuple[str, str]:
    preferred_types = {
        "aws": ["direct_connect", "vpn_connection", "transit_gateway", "vpc"],
        "azure": ["expressroute", "virtual_network_gateway", "vnet"],
        "gcp": ["ha_vpn_gateway", "cloud_router", "vpc"],
    }.get(provider, ["vpc", "vnet"])

    type_to_conn = {
        "direct_connect": "direct_connect",
        "vpn_connection": "vpn",
        "transit_gateway": "transit_gateway_attachment",
        "expressroute": "expressroute",
        "virtual_network_gateway": "vpn",
        "ha_vpn_gateway": "vpn",
        "cloud_router": "router_attachment",
        "vpc": "vpn",
        "vnet": "vpn",
    }

    by_type: dict[str, list[dict]] = {}
    for resource in resources:
        resource_type = str(resource.get("resource_type") or "").strip().lower()
        by_type.setdefault(resource_type, []).append(resource)

    for wanted_type in preferred_types:
        candidates = by_type.get(wanted_type, [])
        if candidates:
            chosen = candidates[0]
            uid = str(chosen.get("resource_uid") or "").strip()
            if uid:
                return uid, type_to_conn.get(wanted_type, "vpn")
    return "", "vpn"


async def _build_hybrid_links(
    account: dict,
    resources: list[dict],
    connect_host_ids: list[int],
    *,
    source: str,
) -> list[dict]:
    provider = str(account.get("provider") or "").strip().lower()
    entry_uid, entry_link_type = _pick_hybrid_entry(provider, resources)
    if not entry_uid:
        return []

    hosts = await _resolve_hybrid_hosts(connect_host_ids)
    links: list[dict] = []
    for host in hosts:
        links.append(
            {
                "provider": provider,
                "host_id": host.get("id"),
                "host_label": host.get("hostname") or host.get("ip_address") or f"host-{host.get('id')}",
                "cloud_resource_uid": entry_uid,
                "connection_type": entry_link_type,
                "state": "up",
                "metadata": {
                    "source": source,
                    "host_ip": host.get("ip_address"),
                },
            }
        )
    return links


async def _build_sample_discovery_snapshot(
    account: dict,
    connect_host_ids: list[int],
    include_hybrid_links: bool,
) -> tuple[list[dict], list[dict], list[dict]]:
    provider = str(account.get("provider") or "").strip().lower()
    resources, connections = _sample_snapshot_for_provider(provider)
    if not include_hybrid_links:
        return resources, connections, []
    hybrid_links = await _build_hybrid_links(account, resources, connect_host_ids, source="sample")
    return resources, connections, hybrid_links


async def _build_live_discovery_snapshot(
    account: dict,
    connect_host_ids: list[int],
    include_hybrid_links: bool,
) -> tuple[list[dict], list[dict], list[dict]]:
    resources, connections = await asyncio.to_thread(collect_provider_snapshot, account)
    if not include_hybrid_links:
        return resources, connections, []
    hybrid_links = await _build_hybrid_links(account, resources, connect_host_ids, source="live")
    return resources, connections, hybrid_links


@router.get("/api/cloud/providers")
async def cloud_providers_api():
    capabilities = get_provider_capabilities()
    providers = []
    for provider_id in sorted(_VALID_PROVIDERS):
        info = _PROVIDER_INFO[provider_id]
        caps = capabilities.get(provider_id, {"live_supported": False, "missing_dependencies": []})
        providers.append(
            {
                "id": provider_id,
                "name": info["name"],
                "focus_constructs": list(info["focus_constructs"]),
                "live_supported": bool(caps.get("live_supported")),
                "missing_dependencies": list(caps.get("missing_dependencies") or []),
            }
        )
    return {"providers": providers, "count": len(providers)}


@router.get("/api/cloud/accounts")
async def cloud_accounts_api(
    provider: str | None = Query(default=None),
    enabled_only: bool = Query(default=False),
):
    try:
        normalized_provider = _normalize_provider(provider) if provider else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Unsupported cloud provider") from None

    accounts = await db.list_cloud_accounts(provider=normalized_provider, enabled_only=enabled_only)
    return {"accounts": [_serialize_account(a) for a in accounts], "count": len(accounts)}


@router.post("/api/cloud/accounts", status_code=201, dependencies=[Depends(_require_admin_dep)])
async def create_cloud_account_api(body: CloudAccountCreate, request: Request):
    try:
        provider = _normalize_provider(body.provider)
    except ValueError:
        raise HTTPException(status_code=400, detail="Unsupported cloud provider") from None

    session = _get_session(request) or {}
    user = session.get("user", "")
    account = await db.create_cloud_account(
        provider=provider,
        name=body.name.strip(),
        account_identifier=body.account_identifier.strip(),
        region_scope=body.region_scope.strip(),
        auth_type=body.auth_type.strip() or "manual",
        auth_config_json=body.auth_config,
        notes=body.notes.strip(),
        enabled=1 if body.enabled else 0,
        created_by=user,
    )
    if not account:
        raise HTTPException(status_code=500, detail="Failed to create cloud account")

    await _audit(
        "cloud_visibility",
        "create_account",
        user=user,
        detail=f"{provider}:{body.name.strip()}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "account": _serialize_account(account)}


@router.put("/api/cloud/accounts/{account_id}", dependencies=[Depends(_require_admin_dep)])
async def update_cloud_account_api(account_id: int, body: CloudAccountUpdate, request: Request):
    existing = await db.get_cloud_account(account_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Cloud account not found")

    updates = body.model_dump(exclude_none=True)
    if "provider" in updates:
        try:
            updates["provider"] = _normalize_provider(updates.get("provider"))
        except ValueError:
            raise HTTPException(status_code=400, detail="Unsupported cloud provider") from None
    if "auth_config" in updates:
        updates["auth_config_json"] = updates.pop("auth_config")

    updated = await db.update_cloud_account(account_id, **updates)
    if not updated:
        raise HTTPException(status_code=404, detail="Cloud account not found")

    session = _get_session(request) or {}
    await _audit(
        "cloud_visibility",
        "update_account",
        user=session.get("user", ""),
        detail=f"account_id={account_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "account": _serialize_account(updated)}


@router.delete("/api/cloud/accounts/{account_id}", dependencies=[Depends(_require_admin_dep)])
async def delete_cloud_account_api(account_id: int, request: Request):
    existing = await db.get_cloud_account(account_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Cloud account not found")
    deleted = await db.delete_cloud_account(account_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Cloud account not found")

    session = _get_session(request) or {}
    await _audit(
        "cloud_visibility",
        "delete_account",
        user=session.get("user", ""),
        detail=f"account_id={account_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.post("/api/cloud/accounts/{account_id}/validate", dependencies=[Depends(_require_admin_dep)])
async def validate_cloud_account_api(account_id: int, request: Request, body: CloudValidationRequest | None = None):
    account = await db.get_cloud_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail="Cloud account not found")

    payload = body or CloudValidationRequest()
    mode = (payload.mode or "live").strip().lower()
    if mode not in {"live", "sample"}:
        raise HTTPException(status_code=400, detail="Unsupported validation mode")

    provider = str(account.get("provider") or "").strip().lower()
    capabilities = get_provider_capabilities().get(provider, {})
    missing_dependencies = list(capabilities.get("missing_dependencies") or [])

    valid = True
    status = "ready"
    message = "Cloud validation succeeded"
    resources: list[dict] = []
    connections: list[dict] = []

    if mode == "sample":
        status = "sample"
        message = "Sample-mode validation succeeded"
    else:
        try:
            resources, connections = await asyncio.to_thread(collect_provider_snapshot, account)
            message = "Live provider validation succeeded"
        except CloudCollectorUnavailable:
            valid = False
            status = "unavailable"
            message = "Live collector dependencies are not installed"
        except CloudCollectorAuthError:
            valid = False
            status = "auth_error"
            message = "Live provider authentication/configuration failed"
        except CloudCollectorExecutionError:
            valid = False
            status = "execution_error"
            message = "Live provider validation failed"
        except Exception:
            valid = False
            status = "error"
            message = "Cloud validation failed. Check server logs for details."
            LOGGER.error("cloud validation failed for account_id=%s", account_id, exc_info=True)

    session = _get_session(request) or {}
    await _audit(
        "cloud_visibility",
        "validate_account",
        user=session.get("user", ""),
        detail=f"account_id={account_id} mode={mode} status={status}",
        correlation_id=_corr_id(request),
    )
    return {
        "ok": True,
        "account_id": account_id,
        "provider": provider,
        "mode": mode,
        "valid": valid,
        "status": status,
        "message": message,
        "missing_dependencies": missing_dependencies,
        "resource_sample_count": len(resources),
        "connection_sample_count": len(connections),
    }


@router.post("/api/cloud/accounts/{account_id}/flow-logs/ingest", dependencies=[Depends(_require_admin_dep)])
async def ingest_cloud_flow_logs_api(account_id: int, request: Request, body: CloudFlowIngestRequest):
    account = await db.get_cloud_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail="Cloud account not found")

    flow_format = str(body.format or "normalized").strip().lower()
    if flow_format not in _VALID_FLOW_INGEST_FORMATS:
        raise HTTPException(status_code=400, detail="Unsupported cloud flow ingestion format")
    if not isinstance(body.records, list) or not body.records:
        raise HTTPException(status_code=400, detail="Flow ingestion requires at least one record")
    if len(body.records) > 10000:
        raise HTTPException(status_code=400, detail="Flow ingestion payload exceeds 10,000 records")

    provider = str(account.get("provider") or "").strip().lower()
    try:
        normalized_records = _prepare_flow_ingest_records(provider, flow_format, body.records)
    except ValueError as exc:
        if str(exc) == "mismatched_flow_format_provider":
            raise HTTPException(status_code=400, detail="Flow format must match cloud account provider") from None
        raise HTTPException(status_code=400, detail="Unsupported cloud flow ingestion format") from None

    if not normalized_records:
        raise HTTPException(status_code=400, detail="No valid flow records found in payload")

    flow_rows = _build_flow_rows_for_ingest(account_id, provider, normalized_records)
    inserted = await db.create_flow_records_batch(flow_rows)
    summary = _summarize_flow_records(normalized_records)
    skipped = max(0, len(body.records) - len(normalized_records))

    if body.emit_event:
        message = (
            f"Cloud flow ingest account_id={account_id} provider={provider} "
            f"ingested={inserted} skipped={skipped}"
        )
        raw_data = json.dumps(
            {
                "account_id": account_id,
                "provider": provider,
                "format": flow_format,
                "source": str(body.source or "api"),
                "summary": summary,
            }
        )[:2000]
        await db.create_trap_syslog_event(
            source_ip=f"cloud:{provider}:{account_id}",
            event_type="cloud_flow",
            facility="cloud",
            severity="info",
            message=message,
            raw_data=raw_data,
        )

    session = _get_session(request) or {}
    await _audit(
        "cloud_visibility",
        "ingest_flow_logs",
        user=session.get("user", ""),
        detail=(
            f"account_id={account_id} provider={provider} format={flow_format} "
            f"ingested={inserted} skipped={skipped}"
        ),
        correlation_id=_corr_id(request),
    )
    return {
        "ok": True,
        "account_id": account_id,
        "provider": provider,
        "format": flow_format,
        "source": str(body.source or "api"),
        "ingested": inserted,
        "skipped": skipped,
        "summary": summary,
    }


@router.post("/api/cloud/accounts/{account_id}/traffic-metrics/ingest", dependencies=[Depends(_require_admin_dep)])
async def ingest_cloud_traffic_metrics_api(account_id: int, request: Request, body: CloudTrafficMetricIngestRequest):
    account = await db.get_cloud_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail="Cloud account not found")

    ingest_format = str(body.format or "normalized").strip().lower()
    if ingest_format not in _VALID_TRAFFIC_INGEST_FORMATS:
        raise HTTPException(status_code=400, detail="Unsupported cloud traffic metric ingestion format")
    if not isinstance(body.records, list) or not body.records:
        raise HTTPException(status_code=400, detail="Traffic metric ingestion requires at least one record")
    if len(body.records) > 20000:
        raise HTTPException(status_code=400, detail="Traffic metric ingestion payload exceeds 20,000 records")

    provider = str(account.get("provider") or "").strip().lower()
    try:
        normalized_records = _prepare_traffic_metric_ingest_records(provider, ingest_format, body.records)
    except ValueError as exc:
        if str(exc) == "mismatched_traffic_format_provider":
            raise HTTPException(status_code=400, detail="Traffic metric format must match cloud account provider") from None
        raise HTTPException(status_code=400, detail="Unsupported cloud traffic metric ingestion format") from None

    if not normalized_records:
        raise HTTPException(status_code=400, detail="No valid traffic metric records found in payload")

    metric_rows = _build_traffic_metric_rows_for_ingest(
        account_id,
        provider,
        normalized_records,
        source=str(body.source or "api"),
    )
    inserted = await db.create_cloud_traffic_metrics_batch(metric_rows)
    skipped = max(0, len(body.records) - len(normalized_records))
    summary = _summarize_traffic_metric_records(normalized_records)

    if body.emit_event:
        message = (
            f"Cloud traffic metric ingest account_id={account_id} provider={provider} "
            f"ingested={inserted} skipped={skipped}"
        )
        raw_data = json.dumps(
            {
                "account_id": account_id,
                "provider": provider,
                "format": ingest_format,
                "source": str(body.source or "api"),
                "summary": summary,
            }
        )[:2000]
        await db.create_trap_syslog_event(
            source_ip=f"cloud:{provider}:{account_id}",
            event_type="cloud_traffic_metric",
            facility="cloud",
            severity="info",
            message=message,
            raw_data=raw_data,
        )

    session = _get_session(request) or {}
    await _audit(
        "cloud_visibility",
        "ingest_traffic_metrics",
        user=session.get("user", ""),
        detail=(
            f"account_id={account_id} provider={provider} format={ingest_format} "
            f"ingested={inserted} skipped={skipped}"
        ),
        correlation_id=_corr_id(request),
    )
    return {
        "ok": True,
        "account_id": account_id,
        "provider": provider,
        "format": ingest_format,
        "source": str(body.source or "api"),
        "ingested": inserted,
        "skipped": skipped,
        "summary": summary,
    }


@router.post("/api/cloud/accounts/{account_id}/discover", dependencies=[Depends(_require_admin_dep)])
async def discover_cloud_account_api(account_id: int, request: Request, body: CloudDiscoveryRequest | None = None):
    account = await db.get_cloud_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail="Cloud account not found")

    payload = body or CloudDiscoveryRequest()
    requested_mode = (payload.mode or "auto").strip().lower()
    if requested_mode not in {"sample", "live", "auto"}:
        raise HTTPException(status_code=400, detail="Unsupported discovery mode")

    effective_mode = requested_mode
    fallback_used = False
    sync_status = "success"
    sync_message = ""

    try:
        if requested_mode == "sample":
            resources, connections, hybrid_links = await _build_sample_discovery_snapshot(
                account,
                payload.connect_host_ids,
                payload.include_hybrid_links,
            )
            sync_message = "Sample discovery snapshot refreshed"
        else:
            try:
                resources, connections, hybrid_links = await _build_live_discovery_snapshot(
                    account,
                    payload.connect_host_ids,
                    payload.include_hybrid_links,
                )
                effective_mode = "live"
                sync_message = "Live provider discovery snapshot refreshed"
            except CloudCollectorUnavailable:
                if requested_mode == "live":
                    raise HTTPException(status_code=503, detail="Live discovery dependencies are not installed") from None
                LOGGER.warning("cloud live discovery unavailable account_id=%s; falling back to sample mode", account_id)
                resources, connections, hybrid_links = await _build_sample_discovery_snapshot(
                    account,
                    payload.connect_host_ids,
                    payload.include_hybrid_links,
                )
                effective_mode = "sample"
                fallback_used = True
                sync_status = "warning"
                sync_message = "Live discovery unavailable; sample snapshot used"
            except CloudCollectorAuthError:
                if requested_mode == "live":
                    raise HTTPException(status_code=400, detail="Live discovery authentication/configuration failed") from None
                LOGGER.warning("cloud live discovery auth failure account_id=%s; falling back to sample mode", account_id)
                resources, connections, hybrid_links = await _build_sample_discovery_snapshot(
                    account,
                    payload.connect_host_ids,
                    payload.include_hybrid_links,
                )
                effective_mode = "sample"
                fallback_used = True
                sync_status = "warning"
                sync_message = "Live discovery authentication failed; sample snapshot used"
            except CloudCollectorExecutionError:
                if requested_mode == "live":
                    raise HTTPException(status_code=502, detail="Live provider discovery failed") from None
                LOGGER.warning("cloud live discovery execution failure account_id=%s; falling back to sample mode", account_id)
                resources, connections, hybrid_links = await _build_sample_discovery_snapshot(
                    account,
                    payload.connect_host_ids,
                    payload.include_hybrid_links,
                )
                effective_mode = "sample"
                fallback_used = True
                sync_status = "warning"
                sync_message = "Live discovery failed; sample snapshot used"

        summary = await db.replace_cloud_discovery_snapshot(
            account_id,
            resources=resources,
            connections=connections,
            hybrid_links=hybrid_links,
            sync_status=sync_status,
            sync_message=sync_message,
        )
    except HTTPException:
        raise
    except Exception:
        LOGGER.error("cloud visibility discovery failed for account_id=%s", account_id, exc_info=True)
        await db.set_cloud_account_sync_status(
            account_id,
            status="error",
            message="Discovery failed. Check server logs for details.",
        )
        raise HTTPException(status_code=500, detail="Cloud discovery failed") from None

    session = _get_session(request) or {}
    await _audit(
        "cloud_visibility",
        "discover_snapshot",
        user=session.get("user", ""),
        detail=f"account_id={account_id} requested_mode={requested_mode} effective_mode={effective_mode}",
        correlation_id=_corr_id(request),
    )
    return {
        "ok": True,
        "account_id": account_id,
        "requested_mode": requested_mode,
        "effective_mode": effective_mode,
        "fallback_used": fallback_used,
        "message": sync_message,
        "summary": summary,
    }


@router.get("/api/cloud/flow-logs/summary")
async def cloud_flow_summary_api(
    account_id: int | None = Query(default=None),
    provider: str | None = Query(default=None),
    hours: int = Query(default=24, ge=1, le=720),
):
    try:
        normalized_provider = _normalize_provider(provider) if provider else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Unsupported cloud provider") from None

    summary = await db.get_cloud_flow_summary(
        account_id=account_id,
        provider=normalized_provider,
        hours=hours,
    )
    return {
        "summary": summary,
        "hours": hours,
        "account_id": account_id,
        "provider": normalized_provider,
    }


@router.get("/api/cloud/flow-logs/top-talkers")
async def cloud_flow_top_talkers_api(
    account_id: int | None = Query(default=None),
    provider: str | None = Query(default=None),
    hours: int = Query(default=24, ge=1, le=720),
    direction: str = Query(default="src"),
    limit: int = Query(default=20, ge=1, le=200),
):
    try:
        normalized_provider = _normalize_provider(provider) if provider else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Unsupported cloud provider") from None
    direction_mode = str(direction or "src").strip().lower()
    if direction_mode not in {"src", "dst"}:
        raise HTTPException(status_code=400, detail="direction must be 'src' or 'dst'")

    rows = await db.get_cloud_flow_top_talkers(
        account_id=account_id,
        provider=normalized_provider,
        hours=hours,
        direction=direction_mode,
        limit=limit,
    )
    return {
        "talkers": rows,
        "hours": hours,
        "direction": direction_mode,
        "account_id": account_id,
        "provider": normalized_provider,
        "count": len(rows),
    }


@router.get("/api/cloud/flow-logs/timeline")
async def cloud_flow_timeline_api(
    account_id: int | None = Query(default=None),
    provider: str | None = Query(default=None),
    hours: int = Query(default=24, ge=1, le=720),
    bucket_minutes: int = Query(default=5, ge=1, le=60),
):
    try:
        normalized_provider = _normalize_provider(provider) if provider else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Unsupported cloud provider") from None

    rows = await db.get_cloud_flow_timeline(
        account_id=account_id,
        provider=normalized_provider,
        hours=hours,
        bucket_minutes=bucket_minutes,
    )
    return {
        "timeline": rows,
        "hours": hours,
        "bucket_minutes": bucket_minutes,
        "account_id": account_id,
        "provider": normalized_provider,
        "count": len(rows),
    }


@router.get("/api/cloud/traffic-metrics/summary")
async def cloud_traffic_metric_summary_api(
    account_id: int | None = Query(default=None),
    provider: str | None = Query(default=None),
    hours: int = Query(default=24, ge=1, le=720),
):
    try:
        normalized_provider = _normalize_provider(provider) if provider else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Unsupported cloud provider") from None

    summary = await db.get_cloud_traffic_metric_summary(
        account_id=account_id,
        provider=normalized_provider,
        hours=hours,
    )
    return {
        "summary": summary,
        "hours": hours,
        "account_id": account_id,
        "provider": normalized_provider,
    }


@router.get("/api/cloud/traffic-metrics/timeline")
async def cloud_traffic_metric_timeline_api(
    account_id: int | None = Query(default=None),
    provider: str | None = Query(default=None),
    metric_name: str | None = Query(default=None),
    hours: int = Query(default=24, ge=1, le=720),
    bucket_minutes: int = Query(default=5, ge=1, le=60),
):
    try:
        normalized_provider = _normalize_provider(provider) if provider else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Unsupported cloud provider") from None

    rows = await db.get_cloud_traffic_metric_timeline(
        account_id=account_id,
        provider=normalized_provider,
        metric_name=metric_name.strip() if metric_name else None,
        hours=hours,
        bucket_minutes=bucket_minutes,
    )
    return {
        "timeline": rows,
        "hours": hours,
        "bucket_minutes": bucket_minutes,
        "account_id": account_id,
        "provider": normalized_provider,
        "metric_name": metric_name,
        "count": len(rows),
    }


@router.get("/api/cloud/traffic-metrics/top-resources")
async def cloud_traffic_metric_top_resources_api(
    account_id: int | None = Query(default=None),
    provider: str | None = Query(default=None),
    metric_name: str | None = Query(default=None),
    hours: int = Query(default=24, ge=1, le=720),
    limit: int = Query(default=20, ge=1, le=200),
):
    try:
        normalized_provider = _normalize_provider(provider) if provider else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Unsupported cloud provider") from None

    rows = await db.get_cloud_traffic_metric_top_resources(
        account_id=account_id,
        provider=normalized_provider,
        metric_name=metric_name.strip() if metric_name else None,
        hours=hours,
        limit=limit,
    )
    return {
        "resources": rows,
        "hours": hours,
        "account_id": account_id,
        "provider": normalized_provider,
        "metric_name": metric_name,
        "count": len(rows),
    }


@router.get("/api/cloud/resources")
async def cloud_resources_api(
    account_id: int | None = Query(default=None),
    provider: str | None = Query(default=None),
    resource_type: str | None = Query(default=None),
):
    try:
        normalized_provider = _normalize_provider(provider) if provider else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Unsupported cloud provider") from None

    resources = await db.get_cloud_resources(
        account_id=account_id,
        provider=normalized_provider,
        resource_type=(resource_type.strip() if resource_type else None),
    )
    return {"resources": [_serialize_resource(r) for r in resources], "count": len(resources)}


@router.get("/api/cloud/connections")
async def cloud_connections_api(
    account_id: int | None = Query(default=None),
    provider: str | None = Query(default=None),
):
    try:
        normalized_provider = _normalize_provider(provider) if provider else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Unsupported cloud provider") from None

    connections = await db.get_cloud_connections(account_id=account_id, provider=normalized_provider)
    return {"connections": [_serialize_connection(c) for c in connections], "count": len(connections)}


@router.get("/api/cloud/hybrid-links")
async def cloud_hybrid_links_api(
    account_id: int | None = Query(default=None),
    provider: str | None = Query(default=None),
):
    try:
        normalized_provider = _normalize_provider(provider) if provider else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Unsupported cloud provider") from None

    links = await db.get_cloud_hybrid_links(account_id=account_id, provider=normalized_provider)
    return {"links": [_serialize_hybrid_link(link) for link in links], "count": len(links)}


@router.get("/api/cloud/policies/rules")
async def cloud_policy_rules_api(
    account_id: int | None = Query(default=None),
    provider: str | None = Query(default=None),
    resource_uid: str | None = Query(default=None),
    direction: str | None = Query(default=None),
    action: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=2000),
):
    try:
        provider_value = provider if isinstance(provider, str) else None
        normalized_provider = _normalize_provider(provider_value) if provider_value else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Unsupported cloud provider") from None

    direction_value = direction if isinstance(direction, str) else None
    normalized_direction = str(direction_value or "").strip().lower() or None
    if normalized_direction and normalized_direction not in {"inbound", "outbound", "ingress", "egress"}:
        raise HTTPException(status_code=400, detail="Unsupported policy direction")
    if normalized_direction == "ingress":
        normalized_direction = "inbound"
    elif normalized_direction == "egress":
        normalized_direction = "outbound"

    action_value = action if isinstance(action, str) else None
    normalized_action = str(action_value or "").strip().lower() or None
    if normalized_action and normalized_action not in {"allow", "deny"}:
        raise HTTPException(status_code=400, detail="Unsupported policy action")

    resource_uid_value = resource_uid if isinstance(resource_uid, str) else None

    limit_value = limit if isinstance(limit, int) else 200

    rules = await db.get_cloud_policy_rules(
        account_id=account_id,
        provider=normalized_provider,
        resource_uid=resource_uid_value.strip() if resource_uid_value else None,
        direction=normalized_direction,
        action=normalized_action,
        limit=limit_value,
    )
    return {"rules": [_serialize_policy_rule(rule) for rule in rules], "count": len(rules)}


@router.get("/api/cloud/policies/effective")
async def cloud_policy_effective_views_api(
    account_id: int | None = Query(default=None),
    provider: str | None = Query(default=None),
):
    try:
        provider_value = provider if isinstance(provider, str) else None
        normalized_provider = _normalize_provider(provider_value) if provider_value else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Unsupported cloud provider") from None

    rows = await db.get_cloud_policy_effective_views(account_id=account_id, provider=normalized_provider)
    return {"resources": rows, "count": len(rows)}


@router.get("/api/cloud/topology")
async def cloud_topology_api(
    account_id: int | None = Query(default=None),
    provider: str | None = Query(default=None),
):
    try:
        normalized_provider = _normalize_provider(provider) if provider else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Unsupported cloud provider") from None

    snapshot = await db.get_cloud_topology_snapshot(account_id=account_id, provider=normalized_provider)
    return {
        "accounts": [_serialize_account(a) for a in snapshot.get("accounts", []) if a],
        "resources": [_serialize_resource(r) for r in snapshot.get("resources", [])],
        "connections": [_serialize_connection(c) for c in snapshot.get("connections", [])],
        "hybrid_links": [_serialize_hybrid_link(link) for link in snapshot.get("hybrid_links", [])],
        "summary": snapshot.get("summary", {}),
    }


# ═══════════════════════════════════════════════════════════════════════════
# Cloud Flow Sync Configuration & Manual Pull
# ═══════════════════════════════════════════════════════════════════════════


class CloudFlowSyncConfigUpdate(BaseModel):
    enabled: bool | None = None
    interval_seconds: int | None = None
    lookback_minutes: int | None = None


class CloudTrafficSyncConfigUpdate(BaseModel):
    enabled: bool | None = None
    interval_seconds: int | None = None
    lookback_minutes: int | None = None


@router.get("/api/cloud/flow-sync/config")
async def get_cloud_flow_sync_config_api():
    import netcontrol.routes.state as state
    return {"config": dict(state.CLOUD_FLOW_SYNC_CONFIG), "status": dict(state.CLOUD_FLOW_SYNC_STATUS)}


@router.put("/api/cloud/flow-sync/config", dependencies=[Depends(_require_admin_dep)])
async def update_cloud_flow_sync_config_api(request: Request, body: CloudFlowSyncConfigUpdate):
    import netcontrol.routes.state as state

    current = dict(state.CLOUD_FLOW_SYNC_CONFIG)
    if body.enabled is not None:
        current["enabled"] = body.enabled
    if body.interval_seconds is not None:
        current["interval_seconds"] = body.interval_seconds
    if body.lookback_minutes is not None:
        current["lookback_minutes"] = body.lookback_minutes

    sanitized = state._sanitize_cloud_flow_sync_config(current)
    state.CLOUD_FLOW_SYNC_CONFIG = sanitized
    await db.set_auth_setting("cloud_flow_sync", sanitized)

    session = _get_session(request) or {}
    await _audit(
        "cloud_visibility",
        "update_flow_sync_config",
        user=session.get("user", ""),
        detail=f"enabled={sanitized['enabled']} interval={sanitized['interval_seconds']}s",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "config": sanitized}


@router.post("/api/cloud/flow-sync/pull", dependencies=[Depends(_require_admin_dep)])
async def trigger_cloud_flow_sync_api(
    request: Request,
    account_id: int | None = Query(default=None),
):
    """Manually trigger cloud flow-log pull for one or all accounts."""
    from netcontrol.routes.cloud_flow_pullers import (
        pull_flow_logs_all_accounts,
        pull_flow_logs_for_account,
    )

    if account_id is not None:
        account = await db.get_cloud_account(account_id)
        if not account:
            raise HTTPException(status_code=404, detail="Cloud account not found")
        result = await pull_flow_logs_for_account(account)
        result["account_id"] = account_id
        status = await persist_cloud_flow_sync_status(
            build_cloud_sync_status(
                result,
                source="manual",
                scope="account",
                account_id=account_id,
                account_name=str(account.get("name") or "").strip(),
            )
        )
    else:
        result = await pull_flow_logs_all_accounts()
        status = await persist_cloud_flow_sync_status(
            build_cloud_sync_status(result, source="manual", scope="all")
        )

    session = _get_session(request) or {}
    await _audit(
        "cloud_visibility",
        "manual_flow_sync_pull",
        user=session.get("user", ""),
        detail=f"account_id={account_id} ingested={result.get('ingested', result.get('total_ingested', 0))}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, **result, "status": status}


@router.get("/api/cloud/flow-sync/cursors")
async def get_cloud_flow_sync_cursors_api():
    """Return per-account flow-log sync watermarks."""
    cursors = await db.list_cloud_flow_sync_cursors()
    for c in cursors:
        c["extra"] = _json_loads_safe(c.get("extra_json"), {})
    return {"cursors": cursors, "count": len(cursors)}


# ═══════════════════════════════════════════════════════════════════════════
# Cloud Traffic Metric Sync Configuration & Manual Pull
# ═══════════════════════════════════════════════════════════════════════════


@router.get("/api/cloud/traffic-sync/config")
async def get_cloud_traffic_sync_config_api():
    import netcontrol.routes.state as state

    return {"config": dict(state.CLOUD_TRAFFIC_METRIC_SYNC_CONFIG), "status": dict(state.CLOUD_TRAFFIC_METRIC_SYNC_STATUS)}


@router.put("/api/cloud/traffic-sync/config", dependencies=[Depends(_require_admin_dep)])
async def update_cloud_traffic_sync_config_api(request: Request, body: CloudTrafficSyncConfigUpdate):
    import netcontrol.routes.state as state

    current = dict(state.CLOUD_TRAFFIC_METRIC_SYNC_CONFIG)
    if body.enabled is not None:
        current["enabled"] = body.enabled
    if body.interval_seconds is not None:
        current["interval_seconds"] = body.interval_seconds
    if body.lookback_minutes is not None:
        current["lookback_minutes"] = body.lookback_minutes

    sanitized = state._sanitize_cloud_traffic_metric_sync_config(current)
    state.CLOUD_TRAFFIC_METRIC_SYNC_CONFIG = sanitized
    await db.set_auth_setting("cloud_traffic_metric_sync", sanitized)

    session = _get_session(request) or {}
    await _audit(
        "cloud_visibility",
        "update_traffic_sync_config",
        user=session.get("user", ""),
        detail=f"enabled={sanitized['enabled']} interval={sanitized['interval_seconds']}s",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "config": sanitized}


@router.post("/api/cloud/traffic-sync/pull", dependencies=[Depends(_require_admin_dep)])
async def trigger_cloud_traffic_sync_api(
    request: Request,
    account_id: int | None = Query(default=None),
):
    """Manually trigger cloud traffic-metric pull for one or all accounts."""
    from netcontrol.routes.cloud_metric_pullers import (
        pull_traffic_metrics_all_accounts,
        pull_traffic_metrics_for_account,
    )

    import netcontrol.routes.state as state

    lookback = int(state.CLOUD_TRAFFIC_METRIC_SYNC_CONFIG.get("lookback_minutes", 15))

    if account_id is not None:
        account = await db.get_cloud_account(account_id)
        if not account:
            raise HTTPException(status_code=404, detail="Cloud account not found")
        result = await pull_traffic_metrics_for_account(account, lookback_minutes=lookback)
        result["account_id"] = account_id
        status = await persist_cloud_traffic_sync_status(
            build_cloud_sync_status(
                result,
                source="manual",
                scope="account",
                account_id=account_id,
                account_name=str(account.get("name") or "").strip(),
            )
        )
    else:
        result = await pull_traffic_metrics_all_accounts(lookback_minutes=lookback)
        status = await persist_cloud_traffic_sync_status(
            build_cloud_sync_status(result, source="manual", scope="all")
        )

    session = _get_session(request) or {}
    await _audit(
        "cloud_visibility",
        "manual_traffic_sync_pull",
        user=session.get("user", ""),
        detail=f"account_id={account_id} ingested={result.get('ingested', result.get('total_ingested', 0))}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, **result, "status": status}


@router.get("/api/cloud/traffic-sync/cursors")
async def get_cloud_traffic_sync_cursors_api():
    """Return per-account traffic-metric sync watermarks."""
    cursors = await db.list_cloud_traffic_metric_sync_cursors()
    for c in cursors:
        c["extra"] = _json_loads_safe(c.get("extra_json"), {})
    return {"cursors": cursors, "count": len(cursors)}
