"""
state.py -- Shared configuration state, defaults, constants, and sanitizers.

All mutable config dicts that are read/written by multiple route modules live
here so that every module can ``import netcontrol.routes.state as state`` and
reference ``state.CONFIG_X`` without circular-import issues.
"""

from __future__ import annotations

import asyncio
import os

# ── Helpers ──────────────────────────────────────────────────────────────────

def _env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_cors_origins() -> list[str]:
    """Return sanitized CORS origin allowlist from APP_CORS_ORIGINS."""
    raw = os.getenv("APP_CORS_ORIGINS", "")
    if not raw.strip():
        return ["http://localhost:8080", "http://127.0.0.1:8080"]
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


# ── Environment-derived constants ────────────────────────────────────────────

APP_HTTPS_ENABLED = _env_flag("APP_HTTPS", False)
APP_HSTS_ENABLED = _env_flag("APP_HSTS", APP_HTTPS_ENABLED)
APP_HSTS_MAX_AGE = int(os.getenv("APP_HSTS_MAX_AGE", "31536000"))
# When true, the app-level middleware redirects plaintext HTTP requests to HTTPS.
# Detects scheme via X-Forwarded-Proto (reverse proxy) or request.url.scheme (direct TLS).
# Defaults to APP_HTTPS so production deployments get redirect automatically.
APP_HTTPS_REDIRECT = _env_flag("APP_HTTPS_REDIRECT", APP_HTTPS_ENABLED)
APP_CORS_ALLOW_ORIGINS = _parse_cors_origins()

DISCOVERY_DEFAULT_TIMEOUT_SECONDS = float(os.getenv("APP_DISCOVERY_TIMEOUT_SECONDS", "0.35"))
DISCOVERY_DEFAULT_MAX_HOSTS = int(os.getenv("APP_DISCOVERY_MAX_HOSTS", "256"))
DISCOVERY_MAX_CONCURRENT_PROBES = int(os.getenv("APP_DISCOVERY_MAX_CONCURRENT_PROBES", "64"))
DISCOVERY_PROBE_PORTS = (22, 443)


# ── SNMP defaults ────────────────────────────────────────────────────────────

SNMP_DISCOVERY_DEFAULTS = {
    "enabled": False,
    "version": "2c",
    "community": "public",
    "port": 161,
    "timeout_seconds": 1.2,
    "retries": 0,
    "v3": {
        "username": "",
        "auth_protocol": "sha",
        "auth_password": "",
        "priv_protocol": "aes128",
        "priv_password": "",
    },
}
SNMP_DISCOVERY_PROFILE_DEFAULTS = {
    "enabled": False,
    "version": "2c",
    "community": "",
    "port": 161,
    "timeout_seconds": 1.2,
    "retries": 0,
    "v3": {
        "username": "",
        "auth_protocol": "sha",
        "auth_password": "",
        "priv_protocol": "aes128",
        "priv_password": "",
    },
}


# ── Discovery sync defaults ─────────────────────────────────────────────────

DISCOVERY_SYNC_DEFAULTS = {
    "enabled": False,
    "interval_seconds": 900,
    "profiles": [],
}
DISCOVERY_SYNC_MIN_INTERVAL_SECONDS = 60
DISCOVERY_SYNC_MAX_INTERVAL_SECONDS = 86400


# ── Topology discovery defaults ──────────────────────────────────────────────

TOPOLOGY_DISCOVERY_DEFAULTS = {
    "enabled": False,
    "interval_seconds": 3600,
}
TOPOLOGY_DISCOVERY_MIN_INTERVAL = 300
TOPOLOGY_DISCOVERY_MAX_INTERVAL = 86400


# ── STP discovery defaults ───────────────────────────────────────────────────

STP_DISCOVERY_DEFAULTS = {
    "enabled": False,
    "interval_seconds": 3600,
    "all_vlans": True,
    "vlan_id": 1,
    "max_vlans": int(os.getenv("APP_STP_SCAN_MAX_VLANS", "64")),
}
STP_DISCOVERY_MIN_INTERVAL = 300
STP_DISCOVERY_MAX_INTERVAL = 86400
STP_DISCOVERY_MIN_MAX_VLANS = 1
STP_DISCOVERY_MAX_MAX_VLANS = 256


# ── Config drift check defaults ─────────────────────────────────────────────

CONFIG_DRIFT_CHECK_DEFAULTS = {
    "enabled": False,
    "interval_seconds": 3600,
    "snapshot_retention_days": 90,
}
CONFIG_DRIFT_CHECK_MIN_INTERVAL = 300
CONFIG_DRIFT_CHECK_MAX_INTERVAL = 86400


# ── Config backup defaults ──────────────────────────────────────────────────

CONFIG_BACKUP_DEFAULTS = {
    "enabled": False,
    "interval_seconds": 300,
}
CONFIG_BACKUP_MIN_INTERVAL = 60
CONFIG_BACKUP_MAX_INTERVAL = 86400
CONFIG_BACKUP_POLICY_MIN_INTERVAL = 3600
CONFIG_BACKUP_POLICY_MAX_INTERVAL = 604800
CONFIG_BACKUP_POLICY_MIN_RETENTION = 1
CONFIG_BACKUP_POLICY_MAX_RETENTION = 365


# ── Compliance check defaults ───────────────────────────────────────────────

COMPLIANCE_CHECK_DEFAULTS = {
    "enabled": False,
    "interval_seconds": 300,
    "retention_days": 90,
}
COMPLIANCE_CHECK_MIN_INTERVAL = 60
COMPLIANCE_CHECK_MAX_INTERVAL = 86400
COMPLIANCE_ASSIGNMENT_MIN_INTERVAL = 3600
COMPLIANCE_ASSIGNMENT_MAX_INTERVAL = 604800


# ── Monitoring defaults ─────────────────────────────────────────────────────

MONITORING_DEFAULTS = {
    "enabled": False,
    "interval_seconds": 300,
    "retention_days": 30,
    "cpu_threshold": 90,
    "memory_threshold": 90,
    "collect_routes": True,
    "collect_vpn": True,
    "escalation_enabled": True,
    "escalation_after_minutes": 30,
    "escalation_check_interval": 60,
    "default_cooldown_minutes": 15,
}
MONITORING_MIN_INTERVAL = 60
MONITORING_MAX_INTERVAL = 86400


# ── Auth & login defaults ───────────────────────────────────────────────────

DEFAULT_LOGIN_RULES = {
    "max_attempts": 5,
    "lockout_time": 900,
    "rate_limit_window": 60,
    "rate_limit_max": 10,
}

# Global API rate-limit defaults — applied to all authenticated API endpoints
# beyond login.  Limits state-changing methods (POST/PUT/DELETE) more tightly
# than read-only (GET).
DEFAULT_API_RATE_LIMIT = {
    "enabled": True,
    "window": 60,               # sliding window in seconds
    "max_read": 120,            # GET requests per window per IP
    "max_write": 40,            # POST/PUT/DELETE requests per window per IP
}
API_RATE_LIMIT = {
    "enabled": _env_flag("APP_API_RATE_LIMIT_ENABLED", DEFAULT_API_RATE_LIMIT["enabled"]),
    "window": int(os.getenv("APP_API_RATE_LIMIT_WINDOW", str(DEFAULT_API_RATE_LIMIT["window"]))),
    "max_read": int(os.getenv("APP_API_RATE_LIMIT_MAX_READ", str(DEFAULT_API_RATE_LIMIT["max_read"]))),
    "max_write": int(os.getenv("APP_API_RATE_LIMIT_MAX_WRITE", str(DEFAULT_API_RATE_LIMIT["max_write"]))),
}

AUTH_CONFIG_DEFAULTS = {
    "provider": "local",
    "default_credential_id": None,
    "job_retention_days": 30,
    "radius": {
        "enabled": False,
        "server": "",
        "port": 1812,
        "secret": "",
        "timeout": 5,
        "fallback_to_local": True,
        "fallback_on_reject": False,
    },
    "ldap": {
        "enabled": False,
        "server": "",
        "port": 389,
        "use_ssl": False,
        "bind_dn": "",
        "bind_password": "",
        "base_dn": "",
        "user_search_filter": "(sAMAccountName={username})",
        "user_dn_template": "",
        "group_search_base": "",
        "group_search_filter": "(&(objectClass=group)(member={user_dn}))",
        "admin_group_dn": "",
        "default_role": "user",
        "timeout": 10,
        "fallback_to_local": True,
        "fallback_on_reject": False,
    },
}

FEATURE_FLAGS = [
    "dashboard",
    "inventory",
    "playbooks",
    "jobs",
    "templates",
    "credentials",
    "topology",
    "config-drift",
    "config-backups",
    "compliance",
    "risk-analysis",
]

RADIUS_DICTIONARY_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "routes", "radius.dictionary")
# Normalize so the path resolves correctly from netcontrol/routes/state.py -> project_root/routes/
RADIUS_DICTIONARY_FILE = os.path.normpath(RADIUS_DICTIONARY_FILE)

JOB_RETENTION_MIN_DAYS = 30
JOB_RETENTION_CLEANUP_INTERVAL_SECONDS = 60 * 60 * 6


# ── Mutable config state (populated at startup, mutated by admin routes) ────

LOGIN_ATTEMPTS: dict = {}
LOCKED_OUT: dict = {}

# Global API rate-limit state — keyed by client IP.
# Each value is a list of ``time.time()`` timestamps of recent requests.
API_RATE_LIMIT_TRACKER: dict[str, list[float]] = {}
API_RATE_LIMIT_LOCK: asyncio.Lock | None = None  # initialised at startup

LOGIN_RULES = dict(DEFAULT_LOGIN_RULES)
AUTH_CONFIG = dict(AUTH_CONFIG_DEFAULTS)
DISCOVERY_SYNC_CONFIG = dict(DISCOVERY_SYNC_DEFAULTS)
SNMP_DISCOVERY_CONFIG = dict(SNMP_DISCOVERY_DEFAULTS)
SNMP_DISCOVERY_PROFILES: dict[int, dict] = {}
SNMP_PROFILES: dict[str, dict] = {}
GROUP_SNMP_ASSIGNMENTS: dict[int, str] = {}
TOPOLOGY_DISCOVERY_CONFIG = dict(TOPOLOGY_DISCOVERY_DEFAULTS)
STP_DISCOVERY_CONFIG = dict(STP_DISCOVERY_DEFAULTS)
CONFIG_DRIFT_CHECK_CONFIG = dict(CONFIG_DRIFT_CHECK_DEFAULTS)
CONFIG_BACKUP_CONFIG = dict(CONFIG_BACKUP_DEFAULTS)
COMPLIANCE_CHECK_CONFIG = dict(COMPLIANCE_CHECK_DEFAULTS)
MONITORING_CONFIG = dict(MONITORING_DEFAULTS)

CLOUD_FLOW_SYNC_DEFAULTS = {
    "enabled": False,
    "interval_seconds": 300,  # 5 minutes
    "lookback_minutes": 15,
}

CLOUD_FLOW_SYNC_MIN_INTERVAL = 60
CLOUD_FLOW_SYNC_MAX_INTERVAL = 3600

CLOUD_FLOW_SYNC_CONFIG: dict = dict(CLOUD_FLOW_SYNC_DEFAULTS)

CLOUD_SYNC_STATUS_DEFAULTS = {
    "last_run_at": "",
    "source": "",
    "scope": "",
    "account_id": None,
    "account_name": "",
    "ok": None,
    "ingested": 0,
    "accounts_processed": 0,
    "error_count": 0,
    "errors": [],
}

CLOUD_FLOW_SYNC_STATUS: dict = dict(CLOUD_SYNC_STATUS_DEFAULTS)

CLOUD_TRAFFIC_METRIC_SYNC_DEFAULTS = {
    "enabled": False,
    "interval_seconds": 300,  # 5 minutes
    "lookback_minutes": 15,
}

CLOUD_TRAFFIC_METRIC_SYNC_MIN_INTERVAL = 60
CLOUD_TRAFFIC_METRIC_SYNC_MAX_INTERVAL = 3600

CLOUD_TRAFFIC_METRIC_SYNC_CONFIG: dict = dict(CLOUD_TRAFFIC_METRIC_SYNC_DEFAULTS)
CLOUD_TRAFFIC_METRIC_SYNC_STATUS: dict = dict(CLOUD_SYNC_STATUS_DEFAULTS)

IPAM_SYNC_DEFAULTS = {
    "enabled": True,
    "interval_seconds": 1800,  # 30 minutes
}

IPAM_SYNC_MIN_INTERVAL = 300   # 5 minutes
IPAM_SYNC_MAX_INTERVAL = 86400  # 24 hours

IPAM_SYNC_CONFIG: dict = dict(IPAM_SYNC_DEFAULTS)


def _sanitize_ipam_sync_config(data: dict | None) -> dict:
    cfg = dict(IPAM_SYNC_DEFAULTS)
    if isinstance(data, dict):
        cfg["enabled"] = bool(data.get("enabled", cfg["enabled"]))
        cfg["interval_seconds"] = int(data.get("interval_seconds", cfg["interval_seconds"]))
        cfg["interval_seconds"] = max(
            IPAM_SYNC_MIN_INTERVAL,
            min(IPAM_SYNC_MAX_INTERVAL, cfg["interval_seconds"]),
        )
    return cfg


# ── Sanitizer functions ─────────────────────────────────────────────────────

def _sanitize_login_rules(data: dict | None) -> dict:
    merged = dict(DEFAULT_LOGIN_RULES)
    if isinstance(data, dict):
        merged.update(data)
    return {
        "max_attempts": max(1, int(merged.get("max_attempts", DEFAULT_LOGIN_RULES["max_attempts"]))),
        "lockout_time": max(1, int(merged.get("lockout_time", DEFAULT_LOGIN_RULES["lockout_time"]))),
        "rate_limit_window": max(1, int(merged.get("rate_limit_window", DEFAULT_LOGIN_RULES["rate_limit_window"]))),
        "rate_limit_max": max(1, int(merged.get("rate_limit_max", DEFAULT_LOGIN_RULES["rate_limit_max"]))),
    }


def _sanitize_auth_config(data: dict | None) -> dict:
    cfg = dict(AUTH_CONFIG_DEFAULTS)
    cfg["radius"] = dict(AUTH_CONFIG_DEFAULTS["radius"])
    cfg["ldap"] = dict(AUTH_CONFIG_DEFAULTS["ldap"])
    if isinstance(data, dict):
        if data.get("provider") in {"local", "radius", "ldap"}:
            cfg["provider"] = data["provider"]
        if "job_retention_days" in data:
            cfg["job_retention_days"] = int(data.get("job_retention_days", cfg["job_retention_days"]))
        if "default_credential_id" in data:
            val = data.get("default_credential_id")
            cfg["default_credential_id"] = int(val) if val is not None else None
        radius = data.get("radius")
        if isinstance(radius, dict):
            cfg["radius"].update({
                "enabled": bool(radius.get("enabled", cfg["radius"]["enabled"])),
                "server": str(radius.get("server", cfg["radius"]["server"])).strip(),
                "port": int(radius.get("port", cfg["radius"]["port"])),
                "secret": str(radius.get("secret", cfg["radius"]["secret"])),
                "timeout": int(radius.get("timeout", cfg["radius"]["timeout"])),
                "fallback_to_local": bool(radius.get("fallback_to_local", cfg["radius"]["fallback_to_local"])),
                "fallback_on_reject": bool(radius.get("fallback_on_reject", cfg["radius"]["fallback_on_reject"])),
            })
    cfg["job_retention_days"] = max(JOB_RETENTION_MIN_DAYS, int(cfg.get("job_retention_days", JOB_RETENTION_MIN_DAYS)))
    cfg["radius"]["port"] = max(1, min(65535, cfg["radius"]["port"]))
    cfg["radius"]["timeout"] = max(1, min(30, cfg["radius"]["timeout"]))
    # LDAP config sanitization
    ldap = data.get("ldap") if isinstance(data, dict) else None
    if isinstance(ldap, dict):
        cfg["ldap"].update({
            "enabled": bool(ldap.get("enabled", cfg["ldap"]["enabled"])),
            "server": str(ldap.get("server", cfg["ldap"]["server"])).strip(),
            "port": int(ldap.get("port", cfg["ldap"]["port"])),
            "use_ssl": bool(ldap.get("use_ssl", cfg["ldap"]["use_ssl"])),
            "bind_dn": str(ldap.get("bind_dn", cfg["ldap"]["bind_dn"])).strip(),
            "bind_password": str(ldap.get("bind_password", cfg["ldap"]["bind_password"])),
            "base_dn": str(ldap.get("base_dn", cfg["ldap"]["base_dn"])).strip(),
            "user_search_filter": str(ldap.get("user_search_filter", cfg["ldap"]["user_search_filter"])).strip(),
            "user_dn_template": str(ldap.get("user_dn_template", cfg["ldap"]["user_dn_template"])).strip(),
            "group_search_base": str(ldap.get("group_search_base", cfg["ldap"]["group_search_base"])).strip(),
            "group_search_filter": str(ldap.get("group_search_filter", cfg["ldap"]["group_search_filter"])).strip(),
            "admin_group_dn": str(ldap.get("admin_group_dn", cfg["ldap"]["admin_group_dn"])).strip(),
            "default_role": str(ldap.get("default_role", cfg["ldap"]["default_role"])).strip(),
            "timeout": int(ldap.get("timeout", cfg["ldap"]["timeout"])),
            "fallback_to_local": bool(ldap.get("fallback_to_local", cfg["ldap"]["fallback_to_local"])),
            "fallback_on_reject": bool(ldap.get("fallback_on_reject", cfg["ldap"]["fallback_on_reject"])),
        })
    cfg["ldap"]["port"] = max(1, cfg["ldap"]["port"])
    cfg["ldap"]["timeout"] = max(1, cfg["ldap"]["timeout"])
    return cfg


def _effective_job_retention_days() -> int:
    return max(JOB_RETENTION_MIN_DAYS, int(AUTH_CONFIG.get("job_retention_days", JOB_RETENTION_MIN_DAYS)))




def _sanitize_discovery_sync_config(data: dict | None) -> dict:
    cfg = {
        "enabled": bool(DISCOVERY_SYNC_DEFAULTS["enabled"]),
        "interval_seconds": int(DISCOVERY_SYNC_DEFAULTS["interval_seconds"]),
        "profiles": [],
    }
    if not isinstance(data, dict):
        return cfg

    cfg["enabled"] = bool(data.get("enabled", cfg["enabled"]))
    cfg["interval_seconds"] = int(data.get("interval_seconds", cfg["interval_seconds"]))
    cfg["interval_seconds"] = max(
        DISCOVERY_SYNC_MIN_INTERVAL_SECONDS,
        min(DISCOVERY_SYNC_MAX_INTERVAL_SECONDS, cfg["interval_seconds"]),
    )

    profiles = data.get("profiles", [])
    if not isinstance(profiles, list):
        return cfg

    sanitized_profiles: list[dict] = []
    for profile in profiles:
        if not isinstance(profile, dict):
            continue
        group_id = profile.get("group_id")
        cidrs = profile.get("cidrs")
        if not isinstance(group_id, int) or group_id <= 0:
            continue
        if not isinstance(cidrs, list) or not cidrs:
            continue
        profile_obj = {
            "group_id": group_id,
            "cidrs": [str(c).strip() for c in cidrs if str(c).strip()],
            "remove_absent": bool(profile.get("remove_absent", False)),
            "use_snmp": bool(profile.get("use_snmp", True)),
            "device_type": str(profile.get("device_type", "unknown")).strip() or "unknown",
            "hostname_prefix": str(profile.get("hostname_prefix", "discovered")).strip() or "discovered",
            "timeout_seconds": float(profile.get("timeout_seconds", DISCOVERY_DEFAULT_TIMEOUT_SECONDS)),
            "max_hosts": int(profile.get("max_hosts", DISCOVERY_DEFAULT_MAX_HOSTS)),
        }
        if not profile_obj["cidrs"]:
            continue
        profile_obj["timeout_seconds"] = max(0.05, min(5.0, profile_obj["timeout_seconds"]))
        profile_obj["max_hosts"] = max(1, min(4096, profile_obj["max_hosts"]))
        sanitized_profiles.append(profile_obj)

    cfg["profiles"] = sanitized_profiles
    return cfg


def _sanitize_topology_discovery_config(data: dict | None) -> dict:
    cfg = {
        "enabled": bool(TOPOLOGY_DISCOVERY_DEFAULTS["enabled"]),
        "interval_seconds": int(TOPOLOGY_DISCOVERY_DEFAULTS["interval_seconds"]),
    }
    if isinstance(data, dict):
        cfg["enabled"] = bool(data.get("enabled", cfg["enabled"]))
        cfg["interval_seconds"] = int(data.get("interval_seconds", cfg["interval_seconds"]))
        cfg["interval_seconds"] = max(
            TOPOLOGY_DISCOVERY_MIN_INTERVAL,
            min(TOPOLOGY_DISCOVERY_MAX_INTERVAL, cfg["interval_seconds"]),
        )
    return cfg


def _sanitize_stp_discovery_config(data: dict | None) -> dict:
    cfg = {
        "enabled": bool(STP_DISCOVERY_DEFAULTS["enabled"]),
        "interval_seconds": int(STP_DISCOVERY_DEFAULTS["interval_seconds"]),
        "all_vlans": bool(STP_DISCOVERY_DEFAULTS["all_vlans"]),
        "vlan_id": int(STP_DISCOVERY_DEFAULTS["vlan_id"]),
        "max_vlans": int(STP_DISCOVERY_DEFAULTS["max_vlans"]),
    }
    if isinstance(data, dict):
        cfg["enabled"] = bool(data.get("enabled", cfg["enabled"]))
        cfg["interval_seconds"] = int(data.get("interval_seconds", cfg["interval_seconds"]))
        cfg["interval_seconds"] = max(
            STP_DISCOVERY_MIN_INTERVAL,
            min(STP_DISCOVERY_MAX_INTERVAL, cfg["interval_seconds"]),
        )
        cfg["all_vlans"] = bool(data.get("all_vlans", cfg["all_vlans"]))
        cfg["vlan_id"] = max(1, min(4094, int(data.get("vlan_id", cfg["vlan_id"]))))
        cfg["max_vlans"] = int(data.get("max_vlans", cfg["max_vlans"]))
        cfg["max_vlans"] = max(
            STP_DISCOVERY_MIN_MAX_VLANS,
            min(STP_DISCOVERY_MAX_MAX_VLANS, cfg["max_vlans"]),
        )
    return cfg


def _sanitize_config_drift_check_config(data: dict | None) -> dict:
    cfg = {
        "enabled": bool(CONFIG_DRIFT_CHECK_DEFAULTS["enabled"]),
        "interval_seconds": int(CONFIG_DRIFT_CHECK_DEFAULTS["interval_seconds"]),
        "snapshot_retention_days": int(CONFIG_DRIFT_CHECK_DEFAULTS["snapshot_retention_days"]),
    }
    if isinstance(data, dict):
        cfg["enabled"] = bool(data.get("enabled", cfg["enabled"]))
        cfg["interval_seconds"] = int(data.get("interval_seconds", cfg["interval_seconds"]))
        cfg["interval_seconds"] = max(
            CONFIG_DRIFT_CHECK_MIN_INTERVAL,
            min(CONFIG_DRIFT_CHECK_MAX_INTERVAL, cfg["interval_seconds"]),
        )
        cfg["snapshot_retention_days"] = max(
            1, min(365, int(data.get("snapshot_retention_days", cfg["snapshot_retention_days"])))
        )
    return cfg


def _sanitize_config_backup_config(data: dict | None) -> dict:
    cfg = {
        "enabled": bool(CONFIG_BACKUP_DEFAULTS["enabled"]),
        "interval_seconds": int(CONFIG_BACKUP_DEFAULTS["interval_seconds"]),
    }
    if isinstance(data, dict):
        cfg["enabled"] = bool(data.get("enabled", cfg["enabled"]))
        cfg["interval_seconds"] = int(data.get("interval_seconds", cfg["interval_seconds"]))
        cfg["interval_seconds"] = max(
            CONFIG_BACKUP_MIN_INTERVAL,
            min(CONFIG_BACKUP_MAX_INTERVAL, cfg["interval_seconds"]),
        )
    return cfg


def _sanitize_compliance_check_config(data: dict | None) -> dict:
    cfg = {
        "enabled": bool(COMPLIANCE_CHECK_DEFAULTS["enabled"]),
        "interval_seconds": int(COMPLIANCE_CHECK_DEFAULTS["interval_seconds"]),
        "retention_days": int(COMPLIANCE_CHECK_DEFAULTS["retention_days"]),
    }
    if isinstance(data, dict):
        cfg["enabled"] = bool(data.get("enabled", cfg["enabled"]))
        cfg["interval_seconds"] = int(data.get("interval_seconds", cfg["interval_seconds"]))
        cfg["interval_seconds"] = max(
            COMPLIANCE_CHECK_MIN_INTERVAL,
            min(COMPLIANCE_CHECK_MAX_INTERVAL, cfg["interval_seconds"]),
        )
        cfg["retention_days"] = max(
            1, min(365, int(data.get("retention_days", cfg["retention_days"])))
        )
    return cfg


def _sanitize_monitoring_config(data: dict | None) -> dict:
    cfg = dict(MONITORING_DEFAULTS)
    if isinstance(data, dict):
        cfg["enabled"] = bool(data.get("enabled", cfg["enabled"]))
        cfg["interval_seconds"] = int(data.get("interval_seconds", cfg["interval_seconds"]))
        cfg["interval_seconds"] = max(
            MONITORING_MIN_INTERVAL,
            min(MONITORING_MAX_INTERVAL, cfg["interval_seconds"]),
        )
        cfg["retention_days"] = max(1, min(365, int(data.get("retention_days", cfg["retention_days"]))))
        cfg["cpu_threshold"] = max(1, min(100, int(data.get("cpu_threshold", cfg["cpu_threshold"]))))
        cfg["memory_threshold"] = max(1, min(100, int(data.get("memory_threshold", cfg["memory_threshold"]))))
        cfg["collect_routes"] = bool(data.get("collect_routes", cfg["collect_routes"]))
        cfg["collect_vpn"] = bool(data.get("collect_vpn", cfg["collect_vpn"]))
        cfg["escalation_enabled"] = bool(data.get("escalation_enabled", cfg["escalation_enabled"]))
        cfg["escalation_after_minutes"] = max(5, min(1440, int(data.get("escalation_after_minutes", cfg["escalation_after_minutes"]))))
        cfg["escalation_check_interval"] = max(30, min(3600, int(data.get("escalation_check_interval", cfg["escalation_check_interval"]))))
        cfg["default_cooldown_minutes"] = max(1, min(1440, int(data.get("default_cooldown_minutes", cfg["default_cooldown_minutes"]))))
    return cfg


def _sanitize_cloud_flow_sync_config(data: dict | None) -> dict:
    cfg = dict(CLOUD_FLOW_SYNC_DEFAULTS)
    if isinstance(data, dict):
        cfg["enabled"] = bool(data.get("enabled", cfg["enabled"]))
        cfg["interval_seconds"] = int(data.get("interval_seconds", cfg["interval_seconds"]))
        cfg["interval_seconds"] = max(
            CLOUD_FLOW_SYNC_MIN_INTERVAL,
            min(CLOUD_FLOW_SYNC_MAX_INTERVAL, cfg["interval_seconds"]),
        )
        cfg["lookback_minutes"] = max(5, min(1440, int(data.get("lookback_minutes", cfg["lookback_minutes"]))))
    return cfg


def _sanitize_cloud_traffic_metric_sync_config(data: dict | None) -> dict:
    cfg = dict(CLOUD_TRAFFIC_METRIC_SYNC_DEFAULTS)
    if isinstance(data, dict):
        cfg["enabled"] = bool(data.get("enabled", cfg["enabled"]))
        cfg["interval_seconds"] = int(data.get("interval_seconds", cfg["interval_seconds"]))
        cfg["interval_seconds"] = max(
            CLOUD_TRAFFIC_METRIC_SYNC_MIN_INTERVAL,
            min(CLOUD_TRAFFIC_METRIC_SYNC_MAX_INTERVAL, cfg["interval_seconds"]),
        )
        cfg["lookback_minutes"] = max(5, min(1440, int(data.get("lookback_minutes", cfg["lookback_minutes"]))))
    return cfg


def _sanitize_cloud_sync_status(data: dict | None) -> dict:
    cfg = dict(CLOUD_SYNC_STATUS_DEFAULTS)
    if isinstance(data, dict):
        cfg["last_run_at"] = str(data.get("last_run_at", cfg["last_run_at"]) or "").strip()
        source = str(data.get("source", cfg["source"]) or "").strip().lower()
        cfg["source"] = source if source in {"manual", "scheduled"} else ""
        scope = str(data.get("scope", cfg["scope"]) or "").strip().lower()
        cfg["scope"] = scope if scope in {"account", "all"} else ""
        account_id = data.get("account_id")
        cfg["account_id"] = int(account_id) if account_id is not None else None
        cfg["account_name"] = str(data.get("account_name", cfg["account_name"]) or "").strip()
        ok_value = data.get("ok")
        cfg["ok"] = bool(ok_value) if isinstance(ok_value, bool) else None
        cfg["ingested"] = max(0, int(data.get("ingested", cfg["ingested"])))
        cfg["accounts_processed"] = max(0, int(data.get("accounts_processed", cfg["accounts_processed"])))
        errors = data.get("errors", [])
        if isinstance(errors, list):
            cfg["errors"] = [str(item).strip() for item in errors if str(item).strip()][:50]
        cfg["error_count"] = max(0, int(data.get("error_count", len(cfg["errors"]))))
    return cfg


def _sanitize_snmp_discovery_config(data: dict | None) -> dict:
    cfg = {
        "enabled": bool(SNMP_DISCOVERY_DEFAULTS["enabled"]),
        "version": str(SNMP_DISCOVERY_DEFAULTS["version"]),
        "community": str(SNMP_DISCOVERY_DEFAULTS["community"]),
        "port": int(SNMP_DISCOVERY_DEFAULTS["port"]),
        "timeout_seconds": float(SNMP_DISCOVERY_DEFAULTS["timeout_seconds"]),
        "retries": int(SNMP_DISCOVERY_DEFAULTS["retries"]),
        "v3": dict(SNMP_DISCOVERY_DEFAULTS["v3"]),
    }
    if isinstance(data, dict):
        cfg["enabled"] = bool(data.get("enabled", cfg["enabled"]))
        version = str(data.get("version", cfg["version"]).strip().lower())
        if version in {"2c", "3"}:
            cfg["version"] = version
        cfg["community"] = str(data.get("community", cfg["community"]))
        cfg["port"] = int(data.get("port", cfg["port"]))
        cfg["timeout_seconds"] = float(data.get("timeout_seconds", cfg["timeout_seconds"]))
        cfg["retries"] = int(data.get("retries", cfg["retries"]))
        if isinstance(data.get("v3"), dict):
            v3 = data["v3"]
            cfg["v3"]["username"] = str(v3.get("username", cfg["v3"]["username"]))
            cfg["v3"]["auth_protocol"] = str(v3.get("auth_protocol", cfg["v3"]["auth_protocol"])).lower()
            cfg["v3"]["auth_password"] = str(v3.get("auth_password", cfg["v3"]["auth_password"]))
            cfg["v3"]["priv_protocol"] = str(v3.get("priv_protocol", cfg["v3"]["priv_protocol"])).lower()
            cfg["v3"]["priv_password"] = str(v3.get("priv_password", cfg["v3"]["priv_password"]))

    cfg["port"] = max(1, min(65535, cfg["port"]))
    cfg["timeout_seconds"] = max(0.2, min(10.0, cfg["timeout_seconds"]))
    cfg["retries"] = max(0, min(5, cfg["retries"]))
    if cfg["v3"]["auth_protocol"] not in {"md5", "sha", "sha256", "sha512"}:
        cfg["v3"]["auth_protocol"] = "sha"
    if cfg["v3"]["priv_protocol"] not in {"des", "aes128", "aes192", "aes256"}:
        cfg["v3"]["priv_protocol"] = "aes128"
    return cfg


def _sanitize_snmp_discovery_profile(group_id: int, data: dict | None) -> dict:
    cfg = {
        "group_id": int(group_id),
        "enabled": bool(SNMP_DISCOVERY_PROFILE_DEFAULTS["enabled"]),
        "version": str(SNMP_DISCOVERY_PROFILE_DEFAULTS["version"]),
        "community": str(SNMP_DISCOVERY_PROFILE_DEFAULTS["community"]),
        "port": int(SNMP_DISCOVERY_PROFILE_DEFAULTS["port"]),
        "timeout_seconds": float(SNMP_DISCOVERY_PROFILE_DEFAULTS["timeout_seconds"]),
        "retries": int(SNMP_DISCOVERY_PROFILE_DEFAULTS["retries"]),
        "v3": dict(SNMP_DISCOVERY_PROFILE_DEFAULTS["v3"]),
    }
    if isinstance(data, dict):
        cfg["enabled"] = bool(data.get("enabled", cfg["enabled"]))
        version = str(data.get("version", cfg["version"]).strip().lower())
        if version in {"2c", "3"}:
            cfg["version"] = version
        cfg["community"] = str(data.get("community", cfg["community"]))
        cfg["port"] = int(data.get("port", cfg["port"]))
        cfg["timeout_seconds"] = float(data.get("timeout_seconds", cfg["timeout_seconds"]))
        cfg["retries"] = int(data.get("retries", cfg["retries"]))
        if isinstance(data.get("v3"), dict):
            v3 = data["v3"]
            cfg["v3"]["username"] = str(v3.get("username", cfg["v3"]["username"]))
            cfg["v3"]["auth_protocol"] = str(v3.get("auth_protocol", cfg["v3"]["auth_protocol"])).lower()
            cfg["v3"]["auth_password"] = str(v3.get("auth_password", cfg["v3"]["auth_password"]))
            cfg["v3"]["priv_protocol"] = str(v3.get("priv_protocol", cfg["v3"]["priv_protocol"])).lower()
            cfg["v3"]["priv_password"] = str(v3.get("priv_password", cfg["v3"]["priv_password"]))

    cfg["port"] = max(1, min(65535, cfg["port"]))
    cfg["timeout_seconds"] = max(0.2, min(10.0, cfg["timeout_seconds"]))
    cfg["retries"] = max(0, min(5, cfg["retries"]))
    if cfg["v3"]["auth_protocol"] not in {"md5", "sha", "sha256", "sha512"}:
        cfg["v3"]["auth_protocol"] = "sha"
    if cfg["v3"]["priv_protocol"] not in {"des", "aes128", "aes192", "aes256"}:
        cfg["v3"]["priv_protocol"] = "aes128"
    return cfg


def _sanitize_snmp_discovery_profiles(data: dict | None) -> dict[int, dict]:
    if not isinstance(data, dict):
        return {}
    profiles: dict[int, dict] = {}
    for key, value in data.items():
        try:
            group_id = int(key)
        except Exception:
            continue
        if group_id <= 0:
            continue
        profiles[group_id] = _sanitize_snmp_discovery_profile(group_id, value)
    return profiles


def _sanitize_snmp_profile(profile_id: str, data: dict | None) -> dict:
    cfg = {
        "id": str(profile_id),
        "name": "",
        "enabled": False,
        "version": "2c",
        "community": "",
        "port": 161,
        "timeout_seconds": 1.2,
        "retries": 0,
        "v3": {
            "username": "",
            "auth_protocol": "sha",
            "auth_password": "",
            "priv_protocol": "aes128",
            "priv_password": "",
        },
    }
    if isinstance(data, dict):
        cfg["name"] = str(data.get("name", cfg["name"])).strip()
        cfg["enabled"] = bool(data.get("enabled", cfg["enabled"]))
        version = str(data.get("version", cfg["version"])).strip().lower()
        if version in {"2c", "3"}:
            cfg["version"] = version
        cfg["community"] = str(data.get("community", cfg["community"]))
        cfg["port"] = int(data.get("port", cfg["port"]))
        cfg["timeout_seconds"] = float(data.get("timeout_seconds", cfg["timeout_seconds"]))
        cfg["retries"] = int(data.get("retries", cfg["retries"]))
        if isinstance(data.get("v3"), dict):
            v3 = data["v3"]
            cfg["v3"]["username"] = str(v3.get("username", cfg["v3"]["username"]))
            cfg["v3"]["auth_protocol"] = str(v3.get("auth_protocol", cfg["v3"]["auth_protocol"])).lower()
            cfg["v3"]["auth_password"] = str(v3.get("auth_password", cfg["v3"]["auth_password"]))
            cfg["v3"]["priv_protocol"] = str(v3.get("priv_protocol", cfg["v3"]["priv_protocol"])).lower()
            cfg["v3"]["priv_password"] = str(v3.get("priv_password", cfg["v3"]["priv_password"]))
    cfg["port"] = max(1, min(65535, cfg["port"]))
    cfg["timeout_seconds"] = max(0.2, min(10.0, cfg["timeout_seconds"]))
    cfg["retries"] = max(0, min(5, cfg["retries"]))
    if cfg["v3"]["auth_protocol"] not in {"md5", "sha", "sha256", "sha512"}:
        cfg["v3"]["auth_protocol"] = "sha"
    if cfg["v3"]["priv_protocol"] not in {"des", "aes128", "aes192", "aes256"}:
        cfg["v3"]["priv_protocol"] = "aes128"
    return cfg


def _sanitize_snmp_profiles(data: dict | None) -> dict[str, dict]:
    if not isinstance(data, dict):
        return {}
    profiles: dict[str, dict] = {}
    for key, value in data.items():
        pid = str(key).strip()
        if not pid:
            continue
        profiles[pid] = _sanitize_snmp_profile(pid, value)
    return profiles


def _sanitize_group_snmp_assignments(data: dict | None) -> dict[int, str]:
    if not isinstance(data, dict):
        return {}
    assignments: dict[int, str] = {}
    for key, value in data.items():
        try:
            group_id = int(key)
        except Exception:
            continue
        if group_id <= 0:
            continue
        pid = str(value).strip()
        if pid:
            assignments[group_id] = pid
    return assignments


def _resolve_snmp_discovery_config(group_id: int | None = None) -> dict:
    effective = _sanitize_snmp_discovery_config(SNMP_DISCOVERY_CONFIG)
    if group_id is None:
        return effective
    # New: check named profile assignment first
    profile_id = GROUP_SNMP_ASSIGNMENTS.get(int(group_id))
    if profile_id and profile_id in SNMP_PROFILES:
        return _sanitize_snmp_discovery_config(SNMP_PROFILES[profile_id])
    # Legacy: fall back to old per-group profiles
    profile = SNMP_DISCOVERY_PROFILES.get(int(group_id))
    if not profile:
        return effective
    merged = dict(effective)
    merged["v3"] = dict(effective.get("v3", {}))
    merged.update({
        "enabled": bool(profile.get("enabled", merged.get("enabled", False))),
        "version": str(profile.get("version", merged.get("version", "2c"))),
        "community": str(profile.get("community", merged.get("community", ""))),
        "port": int(profile.get("port", merged.get("port", 161))),
        "timeout_seconds": float(profile.get("timeout_seconds", merged.get("timeout_seconds", 1.2))),
        "retries": int(profile.get("retries", merged.get("retries", 0))),
    })
    if isinstance(profile.get("v3"), dict):
        merged["v3"].update(profile["v3"])
    return _sanitize_snmp_discovery_config(merged)
