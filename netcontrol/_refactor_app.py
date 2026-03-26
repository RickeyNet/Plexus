"""
One-shot script to refactor app.py:
1. Remove extracted code (jobs, config_drift, config_backups)
2. Add router imports, init calls, and router registrations
3. Add re-exports for test backward compatibility
"""
import re

with open("netcontrol/app.py", encoding="utf-8") as f:
    lines = f.readlines()

content = "".join(lines)

# ============================================================================
# STEP 1: Remove background loops for config drift and config backup
# ============================================================================
# These are between the topology_discovery_loop and the compliance check loop

# Find the start: "async def _run_config_drift_check_once"
# Find the end: just before "# ── Compliance Check Background Loop"
drift_bg_start_marker = "\nasync def _run_config_drift_check_once() -> dict:\n"
drift_bg_end_marker = "\n# ── Compliance Check Background Loop"

s1 = content.find(drift_bg_start_marker)
e1 = content.find(drift_bg_end_marker)
if s1 < 0 or e1 < 0:
    raise ValueError(f"Could not find drift/backup background loops markers: s1={s1}, e1={e1}")

content = (content[:s1] +
    "\n# Config drift and backup background loops extracted to their respective modules\n" +
    content[e1:])

# ============================================================================
# STEP 2: Remove extracted Pydantic models (JobLaunch through ConfigBackupRestoreRequest)
# ============================================================================
model_start_marker = "\nclass JobLaunch(BaseModel):\n"
model_end_marker = "\nclass ComplianceProfileCreate(BaseModel):\n"

s2 = content.find(model_start_marker)
e2 = content.find(model_end_marker)
if s2 < 0 or e2 < 0:
    raise ValueError(f"Could not find model markers: s2={s2}, e2={e2}")

content = (content[:s2] +
    "\n# JobLaunch, Config*Drift*, ConfigBackup* models extracted to route modules\n" +
    content[e2:])

# ============================================================================
# STEP 3: Remove the Jobs section
# (from "# ═══...Jobs" header through the end of the /ws/jobs WebSocket,
#  but keep the /ws/converter-jobs WebSocket)
# ============================================================================
jobs_start_marker = "\n# ═════════════════════════════════════════════════════════════════════════════\n# Jobs\n# ═════════════════════════════════════════════════════════════════════════════\n"
jobs_end_marker = "\n# ── WebSocket for live converter job streaming (import / cleanup) ─────────────\n"

s3 = content.find(jobs_start_marker)
e3 = content.find(jobs_end_marker)
if s3 < 0 or e3 < 0:
    raise ValueError(f"Could not find jobs section markers: s3={s3}, e3={e3}")

content = (content[:s3] +
    "\n# Jobs section extracted to netcontrol/routes/jobs.py\n" +
    content[e3:])

# ============================================================================
# STEP 4: Remove the Config Drift Detection section
# (from "# ═══...Config Drift Detection" through admin drift "run-now" route)
# ============================================================================
drift_start_marker = "\n# ═════════════════════════════════════════════════════════════════════════════\n# Config Drift Detection\n# ═════════════════════════════════════════════════════════════════════════════\n"
drift_end_marker = "\n# ═════════════════════════════════════════════════════════════════════════════\n# Config Backups\n# ═════════════════════════════════════════════════════════════════════════════\n"

s4 = content.find(drift_start_marker)
e4 = content.find(drift_end_marker)
if s4 < 0 or e4 < 0:
    raise ValueError(f"Could not find config drift section markers: s4={s4}, e4={e4}")

content = (content[:s4] +
    "\n# Config Drift section extracted to netcontrol/routes/config_drift.py\n" +
    content[e4:])

# ============================================================================
# STEP 5: Remove the Config Backups section
# (from "# ═══...Config Backups" through admin backup "run-now" route)
# ============================================================================
backup_start_marker = "\n# ═════════════════════════════════════════════════════════════════════════════\n# Config Backups\n# ═════════════════════════════════════════════════════════════════════════════\n"
backup_end_marker = "\n# ═════════════════════════════════════════════════════════════════════════════\n# Compliance Profiles & Scans\n"

s5 = content.find(backup_start_marker)
e5 = content.find(backup_end_marker)
if s5 < 0 or e5 < 0:
    raise ValueError(f"Could not find config backups section markers: s5={s5}, e5={e5}")

content = (content[:s5] +
    "\n# Config Backups section extracted to netcontrol/routes/config_backups.py\n" +
    content[e5:])

# ============================================================================
# STEP 6: Add init calls and router registrations after existing include_router calls
# ============================================================================
# Find the last existing include_router call block (playbooks_router)
registration_marker = """app.include_router(
    playbooks_router,
    dependencies=[Depends(require_auth), Depends(require_feature("playbooks"))],
)"""

s6 = content.find(registration_marker)
if s6 < 0:
    raise ValueError("Could not find playbooks_router registration marker")
insert_pos = s6 + len(registration_marker)

new_registrations = """

# Initialize and register extracted route modules
init_jobs(
    require_auth_fn=require_auth,
    require_feature_fn=require_feature,
    verify_session_token_fn=verify_session_token,
    get_user_features_fn=_get_user_features,
)
app.include_router(
    jobs_router,
    dependencies=[Depends(require_auth), Depends(require_feature("jobs"))],
)

init_config_drift(
    require_auth_fn=require_auth,
    require_feature_fn=require_feature,
    require_admin_fn=require_admin,
    verify_session_token_fn=verify_session_token,
    get_user_features_fn=_get_user_features,
)
app.include_router(
    config_drift_router,
    dependencies=[Depends(require_auth), Depends(require_feature("config-drift"))],
)

init_config_backups(
    require_auth_fn=require_auth,
    require_feature_fn=require_feature,
    require_admin_fn=require_admin,
    verify_session_token_fn=verify_session_token,
    get_user_features_fn=_get_user_features,
)
app.include_router(
    config_backups_router,
    dependencies=[Depends(require_auth), Depends(require_feature("config-backups"))],
)"""

content = content[:insert_pos] + new_registrations + content[insert_pos:]

# ============================================================================
# STEP 7: Remove the _push_config_to_device alias (it was between drift routes)
# It may have already been removed with drift section, but let's check
# ============================================================================
push_alias = "\n_push_config_to_device = shared._push_config_to_device\n"
if push_alias in content:
    content = content.replace(push_alias, "\n")

# ============================================================================
# STEP 8: Add re-exports at the bottom of the file for test compatibility
# ============================================================================
# Check if re-exports already exist
if "# ── Re-exports for test backward compatibility" not in content:
    content += """

# ── Re-exports for test backward compatibility ────────────────────────────
# Tests import these via `import netcontrol.app as app_module; app_module.X`
from netcontrol.routes.config_drift import (
    _analyze_drift_for_host,
    ConfigDriftStatusUpdate,
    get_config_drift_summary,
    get_config_baseline,
    update_config_drift_event_status,
)
from netcontrol.routes.jobs import (
    _MAX_CONCURRENT_JOBS,
    _job_semaphore,
)
"""

with open("netcontrol/app.py", "w", encoding="utf-8") as f:
    f.write(content)

print("Refactoring complete!")
