import pytest
from netcontrol.routes import converter


@pytest.fixture(autouse=True)
def patch_session_store(tmp_path, monkeypatch):
    session_dir = tmp_path / "sessions"
    session_dir.mkdir()
    monkeypatch.setattr(converter, "SESSIONS_DIR", str(session_dir))
    monkeypatch.setattr(converter, "_sessions", {})
    yield session_dir
