import netcontrol.app as app_module
import pytest
import routes.database as db_module


@pytest.mark.asyncio
async def test_authenticate_login_identity_local_provider(monkeypatch):
    monkeypatch.setattr(
        app_module,
        "AUTH_CONFIG",
        {
            "provider": "local",
            "radius": {
                "enabled": False,
                "fallback_to_local": True,
                "fallback_on_reject": False,
            },
        },
    )

    async def fake_verify_user(username, password):
        if username == "admin" and password == "good":
            return {"id": 1, "username": "admin", "display_name": "Admin", "role": "admin"}
        return None

    monkeypatch.setattr(app_module, "verify_user", fake_verify_user)

    user, source, error = await app_module.authenticate_login_identity("admin", "good")

    assert user is not None
    assert source == "local"
    assert error is None


@pytest.mark.asyncio
async def test_authenticate_login_identity_radius_accept(monkeypatch):
    monkeypatch.setattr(
        app_module,
        "AUTH_CONFIG",
        {
            "provider": "radius",
            "radius": {
                "enabled": True,
                "fallback_to_local": True,
                "fallback_on_reject": False,
            },
        },
    )

    async def fake_verify_radius_user(username, password):
        return True, "accept"

    async def fake_upsert_radius_user(username):
        return {"id": 2, "username": username, "display_name": username, "role": "user"}

    async def fake_verify_user(username, password):
        return None

    monkeypatch.setattr(app_module, "verify_radius_user", fake_verify_radius_user)
    monkeypatch.setattr(app_module, "upsert_radius_user", fake_upsert_radius_user)
    monkeypatch.setattr(app_module, "verify_user", fake_verify_user)

    user, source, error = await app_module.authenticate_login_identity("radius-user", "pass")

    assert user is not None
    assert user["username"] == "radius-user"
    assert source == "radius"
    assert error is None


@pytest.mark.asyncio
async def test_authenticate_login_identity_radius_reject_no_fallback(monkeypatch):
    monkeypatch.setattr(
        app_module,
        "AUTH_CONFIG",
        {
            "provider": "radius",
            "radius": {
                "enabled": True,
                "fallback_to_local": True,
                "fallback_on_reject": False,
            },
        },
    )

    async def fake_verify_radius_user(username, password):
        return False, "reject"

    async def fake_verify_user(username, password):
        return {"id": 3, "username": username, "display_name": username, "role": "user"}

    monkeypatch.setattr(app_module, "verify_radius_user", fake_verify_radius_user)
    monkeypatch.setattr(app_module, "verify_user", fake_verify_user)

    user, source, error = await app_module.authenticate_login_identity("user", "bad")

    assert user is None
    assert source is None
    assert error == "Invalid username or password"


@pytest.mark.asyncio
async def test_authenticate_login_identity_radius_error_with_local_fallback(monkeypatch):
    monkeypatch.setattr(
        app_module,
        "AUTH_CONFIG",
        {
            "provider": "radius",
            "radius": {
                "enabled": True,
                "fallback_to_local": True,
                "fallback_on_reject": False,
            },
        },
    )

    async def fake_verify_radius_user(username, password):
        return False, "error"

    async def fake_verify_user(username, password):
        return {"id": 4, "username": username, "display_name": username, "role": "user"}

    monkeypatch.setattr(app_module, "verify_radius_user", fake_verify_radius_user)
    monkeypatch.setattr(app_module, "verify_user", fake_verify_user)

    user, source, error = await app_module.authenticate_login_identity("fallback-user", "good")

    assert user is not None
    assert source == "local-fallback"
    assert error is None


@pytest.mark.asyncio
async def test_authenticate_login_identity_radius_reject_with_override_fallback(monkeypatch):
    monkeypatch.setattr(
        app_module,
        "AUTH_CONFIG",
        {
            "provider": "radius",
            "radius": {
                "enabled": True,
                "fallback_to_local": True,
                "fallback_on_reject": True,
            },
        },
    )

    async def fake_verify_radius_user(username, password):
        return False, "reject"

    async def fake_verify_user(username, password):
        return {"id": 5, "username": username, "display_name": username, "role": "user"}

    monkeypatch.setattr(app_module, "verify_radius_user", fake_verify_radius_user)
    monkeypatch.setattr(app_module, "verify_user", fake_verify_user)

    user, source, error = await app_module.authenticate_login_identity("fallback-reject", "good")

    assert user is not None
    assert source == "local-fallback"
    assert error is None


def test_sanitize_auth_config_enforces_job_retention_minimum():
    cfg = app_module._sanitize_auth_config({"provider": "local", "job_retention_days": 7})
    assert cfg["job_retention_days"] == 30


def test_sanitize_auth_config_applies_converter_retention_defaults():
    cfg = app_module._sanitize_auth_config({"provider": "local"})
    assert cfg["converter_session_retention_days"] == 30
    assert cfg["converter_backup_retention_days"] == 30


def test_sanitize_auth_config_enforces_converter_retention_minimums():
    cfg = app_module._sanitize_auth_config(
        {
            "provider": "local",
            "converter_session_retention_days": 0,
            "converter_backup_retention_days": -10,
        }
    )
    assert cfg["converter_session_retention_days"] == 1
    assert cfg["converter_backup_retention_days"] == 1


@pytest.mark.asyncio
async def test_admin_run_retention_cleanup_now_returns_summary(monkeypatch):
    async def fake_cleanup_expired_jobs():
        return 2

    async def fake_cleanup_expired_converter_sessions():
        return {"sessions_deleted": 1, "snapshots_deleted": 3, "sessions_kept": 4}

    monkeypatch.setattr(app_module, "_cleanup_expired_jobs", fake_cleanup_expired_jobs)
    monkeypatch.setattr(
        app_module,
        "_cleanup_expired_converter_sessions",
        fake_cleanup_expired_converter_sessions,
    )
    monkeypatch.setattr(app_module, "_effective_job_retention_days", lambda: 30)
    monkeypatch.setattr(app_module, "_effective_converter_session_retention_days", lambda: 14)
    monkeypatch.setattr(app_module, "_effective_converter_backup_retention_days", lambda: 7)

    result = await app_module.admin_run_retention_cleanup_now()

    assert result["ok"] is True
    assert result["jobs_deleted"] == 2
    assert result["converter"]["sessions_deleted"] == 1
    assert result["converter"]["snapshots_deleted"] == 3
    assert result["effective_retention_days"]["jobs"] == 30
    assert result["effective_retention_days"]["converter_sessions"] == 14
    assert result["effective_retention_days"]["converter_backups"] == 7


@pytest.mark.asyncio
async def test_delete_expired_jobs_removes_only_old_completed_jobs(tmp_path, monkeypatch):
    db_file = tmp_path / "retention_test.db"
    monkeypatch.setattr(db_module, "DB_PATH", str(db_file))
    await db_module.init_db()

    playbook_id = await db_module.create_playbook("Retention PB", "retention_pb.py")
    group_id = await db_module.create_group("Retention Group", "")

    old_finished = "2024-01-01T00:00:00+00:00"
    recent_finished = "2999-01-01T00:00:00+00:00"

    db = await db_module.get_db()
    try:
        await db.execute(
            """
            INSERT INTO jobs (
                playbook_id, inventory_group_id, dry_run, status, started_at, finished_at, hosts_ok, hosts_failed, hosts_skipped, launched_by
            ) VALUES (?, ?, 1, 'success', ?, ?, 1, 0, 0, 'tester')
            """,
            (playbook_id, group_id, old_finished, old_finished),
        )
        await db.execute(
            """
            INSERT INTO jobs (
                playbook_id, inventory_group_id, dry_run, status, started_at, finished_at, hosts_ok, hosts_failed, hosts_skipped, launched_by
            ) VALUES (?, ?, 1, 'failed', ?, ?, 0, 1, 0, 'tester')
            """,
            (playbook_id, group_id, recent_finished, recent_finished),
        )
        await db.execute(
            """
            INSERT INTO jobs (
                playbook_id, inventory_group_id, dry_run, status, started_at, hosts_ok, hosts_failed, hosts_skipped, launched_by
            ) VALUES (?, ?, 1, 'running', ?, 0, 0, 0, 'tester')
            """,
            (playbook_id, group_id, old_finished),
        )
        await db.commit()
    finally:
        await db.close()

    deleted = await db_module.delete_expired_jobs(30)
    assert deleted == 1

    remaining_jobs = await db_module.get_all_jobs(limit=10)
    remaining_statuses = sorted(job["status"] for job in remaining_jobs)
    assert remaining_statuses == ["failed", "running"]
