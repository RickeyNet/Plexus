"""The dashboard (``GET /api/dashboard``) of an account limited to selected
inventory groups (``netcontrol.object_scope``).

The shared, cached dashboard covers the whole estate; a scoped caller gets
the same keys computed over the hosts and jobs of their scope instead (not
cached: the cache is shared by every user). The topology problem list is
left out: integration entities are not in any inventory group.

``dashboard_for_caller`` then fits either payload to the caller's features.
"""

from __future__ import annotations

import asyncio

import routes.database as db
from routes.db.jobs import job_scope_condition

from netcontrol.object_scope import ObjectScope
from netcontrol.routes.shared import caller_features

# The feature each key of the dashboard payload belongs to: a caller without
# that feature gets the dashboard without the key. ``stats`` (counts only) is
# not listed and goes to every holder of the dashboard feature. ``topology``
# (the state of the entities integrations collect) is the data of
# /api/availability/topology/*, which the monitoring feature gates.
DASHBOARD_KEY_FEATURES: dict[str, str] = {
    "recent_jobs": "jobs",
    "groups": "inventory",
    "monitoring": "monitoring",
    "device_health": "monitoring",
    "open_alerts": "monitoring",
    "topology": "monitoring",
}


async def _scoped_stats(scope: ObjectScope, username: str) -> dict:
    """``get_dashboard_stats`` over the caller's hosts, groups and jobs
    (playbooks are a shared catalogue: all of them)."""
    reach = await scope.reach()
    cond, params = job_scope_condition(scope.read_groups, username)
    conn = await db.get_db(read_only=True)
    try:
        cursor = await conn.execute(
            f"""SELECT
                   (SELECT COUNT(*) FROM playbooks),
                   COUNT(*),
                   COALESCE(SUM(CASE WHEN j.status = 'running' THEN 1 ELSE 0 END), 0),
                   COALESCE(SUM(CASE WHEN j.status = 'success' THEN 1 ELSE 0 END), 0),
                   COALESCE(SUM(CASE WHEN j.status IN ('success', 'failed') THEN 1 ELSE 0 END), 0)
               FROM jobs j WHERE {cond}""",  # noqa: S608  # nosec B608 - fixed SQL with placeholders
            params,
        )
        playbooks, total, running, successful, completed = await cursor.fetchone()
    finally:
        await conn.close()
    return {
        "total_hosts": len(reach.read_hosts),
        "total_groups": len(scope.read_groups),
        "total_playbooks": playbooks,
        "total_jobs": total,
        "running_jobs": running,
        "success_rate": round(successful / completed * 100) if completed > 0 else 0,
    }


async def scoped_dashboard_data(scope: ObjectScope, username: str) -> dict:
    """The dashboard keys for a scoped caller. ``recent_jobs`` holds only the
    jobs ``username`` launched within the scope (a scoped account is never an
    admin); ``dashboard_for_caller`` then drops the keys of features the
    caller does not hold."""
    groups = scope.read_groups
    stats, recent_jobs, all_groups, monitoring, latest_polls, alerts = await asyncio.gather(
        _scoped_stats(scope, username),
        db.get_all_jobs(limit=5, group_ids=groups, launched_by=username, only_launched_by=username),
        db.get_all_groups(),
        db.get_monitoring_summary(group_ids=groups),
        db.get_latest_monitoring_polls(group_ids=groups),
        db.get_monitoring_alerts(acknowledged=False, limit=50, group_ids=groups),
    )
    return {
        "stats": stats,
        "recent_jobs": recent_jobs,
        "groups": scope.filter_groups(all_groups),
        "monitoring": monitoring,
        "device_health": latest_polls,
        "open_alerts": alerts,
    }


async def dashboard_for_caller(request, data: dict, scope: ObjectScope, username: str) -> dict:
    """The dashboard the caller of ``request`` may see: a new dict built from
    ``data`` (the unscoped payload is a cache shared by every user, so it is
    never changed), without the keys of features the caller does not hold
    (``DASHBOARD_KEY_FEATURES``). A non-admin sees only the jobs they
    launched: the unscoped payload holds every user's, so they are read again
    for this caller (``scoped_dashboard_data`` already reads only theirs)."""
    features = await caller_features(request)
    view = {
        key: value
        for key, value in data.items()
        if features is None or DASHBOARD_KEY_FEATURES.get(key) is None or DASHBOARD_KEY_FEATURES[key] in features
    }
    # ``features`` is None for an admin or the API token (every feature).
    if "recent_jobs" in view and scope.unrestricted and features is not None:
        view["recent_jobs"] = await db.get_all_jobs(limit=5, only_launched_by=username)
    return view
