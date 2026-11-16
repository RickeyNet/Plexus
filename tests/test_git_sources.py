"""Git data sources (``netcontrol.git_sources``, ``netcontrol.routes.git_sources``,
``routes.db.git_sources``): remote and branch rules, the git runner's
credential handling, reading a checkout, and a full sync against a local
repository: import, update, removal, read-only ownership, conflicts,
deletion, access and audit."""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import netcontrol.app as app_module
import netcontrol.git_sources as gs
import netcontrol.routes.git_sources as git_routes
import pytest
import routes.database as db
from routes.crypto import encrypt
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client, user_client

BASE = "/api/git-sources"
SECRET = "s3cr3t-token-value-0123"
REMOTE = "https://git.example.com/netops/configs.git"

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _ok(resp, status: int = 200) -> dict:
    assert resp.status_code == status, resp.text
    return resp.json()


# ── Remote, branch and field rules ───────────────────────────────────────────


@pytest.mark.parametrize(
    "url,kind,host",
    [
        ("https://git.example.com/netops/configs.git", "https", "git.example.com"),
        ("https://git.example.com:8443/configs", "https", "git.example.com"),
        ("ssh://git@git.example.com:2222/netops/configs.git", "ssh", "git.example.com"),
        ("git@git.example.com:netops/configs.git", "ssh", "git.example.com"),
        ("  https://192.0.2.10/configs.git  ", "https", "192.0.2.10"),
    ],
)
def test_accepted_remotes(url, kind, host):
    remote = gs.parse_remote(url)
    assert (remote.kind, remote.host, remote.url) == (kind, host, url.strip())


@pytest.mark.parametrize(
    "url",
    [
        "",
        "file:///srv/repos/configs.git",
        "FILE:///srv/repos/configs.git",
        "ext::sh -c touch% /tmp/pwned",
        "ext::sh",
        "fd::17",
        "git://git.example.com/configs.git",
        "http://git.example.com/configs.git",
        "/srv/repos/configs.git",
        "C:/repos/configs",
        "../configs",
        "https://user:pass@git.example.com/configs.git",
        "https://token@git.example.com/configs.git",
        "ssh://git:pass@git.example.com/configs.git",
        "-uhttps://git.example.com/x",
        "git@git.example.com:-oProxyCommand=x",
        "https://git.example.com",
        "https://git.example.com/",
        "https://-x.example.com/configs",
        "https://git.example.com/a b",
        "https://git.example.com:99999/x",
    ],
)
def test_rejected_remotes(url):
    with pytest.raises(gs.GitSourceError):
        gs.parse_remote(url)


@pytest.mark.parametrize("branch", ["main", "release/2026.11", "feature_x-1"])
def test_accepted_branches(branch):
    assert gs.clean_branch(branch) == branch


@pytest.mark.parametrize(
    "branch", ["", "-x", ".hidden", "a..b", "a//b", "a/", "a.lock", "a b", "a~1", "a:b", "x" * 201]
)
def test_rejected_branches(branch):
    with pytest.raises(gs.GitSourceError):
        gs.clean_branch(branch)


def test_provides_and_interval_rules():
    assert gs.clean_provides(["config_contexts", "templates", "templates"]) == ["templates", "config_contexts"]
    for bad in ([], ["scripts"], "templates"):
        with pytest.raises(gs.GitSourceError):
            gs.clean_provides(bad)
    assert gs.clean_interval(0) == 0 and gs.clean_interval(60) == 60
    for bad in (1, 4, gs.INTERVAL_MAX_MINUTES + 1, True, "60"):
        with pytest.raises(gs.GitSourceError):
            gs.clean_interval(bad)


# ── git runner: credentials never on the command line or in errors ───────────


def test_scrub_masks_secrets_and_url_userinfo():
    auth = gs.GitAuth(username="svc", password=SECRET)
    text = f"fatal: auth {SECRET} for https://svc:{SECRET}@git.example.com/x Basic {auth.secrets()[-1]}"
    out = gs.scrub(text, auth.secrets())
    assert SECRET not in out and auth.secrets()[-1] not in out
    assert "https://***@git.example.com/x" in out


def test_https_credentials_go_in_the_environment(monkeypatch, tmp_path):
    calls: list[tuple[list[str], dict]] = []

    def fake_run(args, **kw):
        calls.append((list(args), dict(kw["env"])))
        out = "0123456789abcdef0123456789abcdef01234567\n" if "rev-parse" in args else ""
        return subprocess.CompletedProcess(args, 0, stdout=out, stderr="")

    monkeypatch.setattr(gs.shutil, "which", lambda name: "/usr/bin/git")
    monkeypatch.setattr(gs.subprocess, "run", fake_run)
    monkeypatch.setenv("GIT_DIR", "/elsewhere")
    remote = gs.parse_remote(REMOTE)
    sha = gs.fetch_checkout(str(tmp_path / "w"), remote, "main", gs.GitAuth("svc", SECRET), str(tmp_path / "kh"))
    assert sha == "0123456789abcdef0123456789abcdef01234567"
    commands = [a[1:] for a, _ in calls]
    assert [c[2] if c[0] == "-C" else c[0] for c in commands] == ["init", "fetch", "checkout", "clean", "rev-parse"]
    fetch = next(c for c in commands if "fetch" in c)
    assert fetch[-3:] == ["--", REMOTE, "refs/heads/main"]
    token = gs.GitAuth("svc", SECRET).secrets()[-1]
    for args, env in calls:
        assert not any(SECRET in a or token in a for a in args)
        assert env["GIT_TERMINAL_PROMPT"] == "0" and env["GIT_ALLOW_PROTOCOL"] == "https:ssh"
        assert env["GIT_CONFIG_NOSYSTEM"] == "1" and "GIT_DIR" not in env
        assert env["GIT_CONFIG_GLOBAL"] == os.devnull
        config = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"] for i in range(int(env["GIT_CONFIG_COUNT"]))}
        assert config["http.extraHeader"] == f"Authorization: Basic {token}"
        assert config["credential.helper"] == "" and config["core.symlinks"] == "false"


def test_ssh_key_is_a_private_temporary_file(monkeypatch, tmp_path):
    seen: dict = {}

    def fake_run(args, **kw):
        command = kw["env"].get("GIT_SSH_COMMAND", "")
        seen["command"] = command
        key = command.split("-i ", 1)[1].split(" ", 1)[0].strip("'")
        seen["key"] = key
        seen["key_text"] = Path(key).read_text()
        out = "0123456789abcdef0123456789abcdef01234567\n" if "rev-parse" in args else ""
        assert not any(str(v).startswith("Authorization") for v in kw["env"].values())
        return subprocess.CompletedProcess(args, 0, stdout=out, stderr="")

    monkeypatch.setattr(gs.shutil, "which", lambda name: "/usr/bin/git")
    monkeypatch.setattr(gs.subprocess, "run", fake_run)
    key_text = "-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-real-key\n-----END OPENSSH PRIVATE KEY-----"
    remote = gs.parse_remote("git@git.example.com:netops/configs.git")
    gs.fetch_checkout(
        str(tmp_path / "w"), remote, "main", gs.GitAuth("git", private_key=key_text), str(tmp_path / "kh")
    )
    assert "BatchMode=yes" in seen["command"] and "StrictHostKeyChecking=accept-new" in seen["command"]
    assert seen["key_text"].startswith("-----BEGIN") and key_text not in seen["command"]
    assert not Path(seen["key"]).exists()  # removed after the command


def test_git_errors_are_scrubbed_and_timeouts_reported(monkeypatch, tmp_path):
    monkeypatch.setattr(gs.shutil, "which", lambda name: "/usr/bin/git")

    def failing(args, **kw):
        return subprocess.CompletedProcess(args, 128, stdout="", stderr=f"fatal: bad credentials {SECRET}")

    monkeypatch.setattr(gs.subprocess, "run", failing)
    with pytest.raises(gs.GitSourceError) as exc:
        gs.run_git(["fetch", "--", REMOTE], env={}, secrets=[SECRET])
    assert SECRET not in str(exc.value) and "git fetch failed" in str(exc.value)

    def slow(args, **kw):
        raise subprocess.TimeoutExpired(args, kw["timeout"])

    monkeypatch.setattr(gs.subprocess, "run", slow)
    with pytest.raises(gs.GitSourceError, match="timed out after 5 seconds"):
        gs.run_git(["-C", str(tmp_path), "fetch"], env={}, timeout=5)
    monkeypatch.setattr(gs.shutil, "which", lambda name: None)
    with pytest.raises(gs.GitSourceError, match="git is not installed"):
        gs.run_git(["status"], env={})


# ── Reading a checkout ───────────────────────────────────────────────────────


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


PLAYBOOK = "- name: Save the running config\n  hosts: all\n  tasks: []\n"
CONTEXT_YAML = """_metadata:
  name: ntp-servers
  weight: 50
  description: NTP for every device
ntp:
  - 192.0.2.1
  - 198.51.100.1
"""


def test_collect_items_reads_each_content_type(tmp_path):
    _write(tmp_path, "templates/banner.j2", "banner motd ^Authorized use only^\n")
    _write(tmp_path, "templates/cisco_ios/banner.j2", "banner login ^IOS^\n")
    _write(tmp_path, "templates/Bad Driver/x.j2", "x")
    _write(tmp_path, "templates/a/b/too-deep.j2", "x")
    _write(tmp_path, "templates/readme.md", "not a template")
    _write(tmp_path, "templates/.hidden.j2", "x")
    _write(tmp_path, "playbooks/save-config.yml", PLAYBOOK)
    _write(tmp_path, "playbooks/broken.yml", "a: [b\n")
    _write(tmp_path, "playbooks/mapping.yaml", "name: not a list\n")
    _write(tmp_path, "playbooks/bad name.yml", PLAYBOOK)
    _write(tmp_path, "playbooks/tool.py", "print('hi')\n")
    _write(tmp_path, "config_contexts/ntp.yml", CONTEXT_YAML)
    _write(tmp_path, "config_contexts/syslog.json", '{"syslog": {"host": "192.0.2.30"}}')
    _write(tmp_path, "config_contexts/list.json", "[1, 2]")
    _write(tmp_path, "config_contexts/bad-meta.json", '{"_metadata": {"colour": "red"}}')
    _write(tmp_path, "config_contexts/zz-dup.json", '{"_metadata": {"name": "NTP-Servers"}, "a": 1}')
    (tmp_path / "templates" / "huge.j2").write_text("x" * (gs.FILE_MAX_BYTES + 1))

    found = gs.collect_items(str(tmp_path), gs.CONTENT_TYPES)
    templates = {(i.values["name"], i.values["device_type"]): i for i in found.items["templates"]}
    assert set(templates) == {("banner", ""), ("banner", "cisco_ios")}
    assert templates[("banner", "cisco_ios")].path == "templates/cisco_ios/banner.j2"
    [playbook] = found.items["playbooks"]
    assert playbook.values == {
        "name": "save-config",
        "filename": "save-config.yml",
        "type": "ansible",
        "description": "Save the running config",
        "tags": "[]",
        "content": PLAYBOOK,
    }
    contexts = {i.values["name"]: i.values for i in found.items["config_contexts"]}
    assert set(contexts) == {"ntp-servers", "syslog"}
    assert contexts["ntp-servers"]["weight"] == 50 and contexts["ntp-servers"]["data"] == (
        '{"ntp":["192.0.2.1","198.51.100.1"]}'
    )
    assert contexts["syslog"]["weight"] == 1000 and contexts["syslog"]["enabled"] == 1
    warned = {w["path"] for w in found.warnings}
    assert warned >= {
        "templates/Bad Driver/x.j2",
        "templates/a/b/too-deep.j2",
        "templates/huge.j2",
        "playbooks/broken.yml",
        "playbooks/mapping.yaml",
        "playbooks/bad name.yml",
        "config_contexts/list.json",
        "config_contexts/bad-meta.json",
        "config_contexts/zz-dup.json",
    }
    assert "templates/readme.md" not in warned and "templates/.hidden.j2" not in warned
    assert gs.ignored_python_playbooks(str(tmp_path)) == ["playbooks/tool.py"]
    # Only the provided types are read.
    assert set(gs.collect_items(str(tmp_path), ["playbooks"]).items) == {"playbooks"}


def test_collect_items_skips_symbolic_links(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("server secret")
    (tmp_path / "repo" / "templates").mkdir(parents=True)
    try:
        (tmp_path / "repo" / "templates" / "leak.j2").symlink_to(outside)
    except OSError:
        pytest.skip("symbolic links are not available")
    found = gs.collect_items(str(tmp_path / "repo"), ["templates"])
    assert found.items["templates"] == []
    assert [w["path"] for w in found.warnings] == ["templates/leak.j2"]


# ── Sync against a local repository ──────────────────────────────────────────


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=Plexus Test", "-c", "user.email=test@example.com", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


class Repo:
    """A local repository the sync fetches from (through the ``file``
    transport, allowed only by this test's patch)."""

    def __init__(self, path: Path):
        self.path = path
        path.mkdir()
        _git(path, "init", "-q")
        _git(path, "checkout", "-q", "-b", "main")

    def write(self, rel: str, text: str) -> None:
        _write(self.path, rel, text)

    def remove(self, rel: str) -> None:
        (self.path / rel).unlink()

    def commit(self, message: str = "change") -> str:
        _git(self.path, "add", "-A")
        _git(self.path, "commit", "-q", "-m", message)
        return _git(self.path, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path, monkeypatch) -> Repo:
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    data = tmp_path / "data"
    monkeypatch.setenv("PLEXUS_GIT_SOURCES_DIR", str(data))
    monkeypatch.setattr(gs, "ALLOWED_PROTOCOLS", "file")
    repo = Repo(tmp_path / "upstream")
    monkeypatch.setattr(git_routes, "_remote_for", lambda source: gs.Remote("https", "127.0.0.1", repo.path.as_posix()))
    return repo


def _service_credential(password: str = SECRET) -> int:
    return int(asyncio.run(db.create_credential("git-bot", "svc", encrypt(password), is_service=True)))


def _source(admin: CsrfClient, **extra) -> dict:
    body = {"name": "netops-configs", "remote_url": REMOTE, "branch": "main", **extra}
    return _ok(admin.post(BASE, json=body), 201)


def _sync(admin: CsrfClient, source_id: int) -> dict:
    return _ok(admin.post(f"{BASE}/{source_id}/sync"))


def _by_name(rows: list[dict], name: str) -> dict:
    return next(r for r in rows if r["name"] == name)


def _seed(repo: Repo) -> str:
    repo.write("templates/banner.j2", "banner motd ^one^\n")
    repo.write("templates/cisco_ios/banner.j2", "banner login ^ios^\n")
    repo.write("playbooks/save-config.yml", PLAYBOOK)
    repo.write("config_contexts/ntp.yml", CONTEXT_YAML)
    repo.write("README.md", "configs for Plexus\n")
    return repo.commit("seed")


def test_sync_imports_updates_and_removes(admin, repo):
    first = _seed(repo)
    source = _source(admin, credential_id=_service_credential())
    assert source["status"] == "never" and source["credential_name"] == "git-bot"
    assert SECRET not in str(source)

    out = _sync(admin, source["id"])
    assert out["ok"] is True and out["source"]["status"] == "ok" and out["source"]["last_commit"] == first
    counts = out["result"]["counts"]
    assert counts["templates"]["created"] == 2 and counts["playbooks"]["created"] == 1
    assert counts["config_contexts"]["created"] == 1
    assert out["source"]["object_counts"] == {"templates": 2, "playbooks": 1, "config_contexts": 1}
    assert out["source"]["last_synced_at"] and out["source"]["last_attempt_at"]

    templates = [t for t in _ok(admin.get("/api/templates")) if t["git_source_id"] == source["id"]]
    assert {(t["name"], t["device_type"]) for t in templates} == {("banner", ""), ("banner", "cisco_ios")}
    banner = next(t for t in templates if t["device_type"] == "")
    assert banner["git_source_name"] == "netops-configs" and banner["git_commit"] == first
    assert banner["git_path"] == "templates/banner.j2" and banner["content"] == "banner motd ^one^\n"
    playbook = _by_name(_ok(admin.get("/api/playbooks")), "save-config")
    assert playbook["type"] == "ansible" and playbook["git_source_id"] == source["id"]
    context = _by_name(_ok(admin.get("/api/intended-config/contexts"))["contexts"], "ntp-servers")
    assert context["git_source_name"] == "netops-configs" and context["weight"] == 50
    assert context["data"] == {"ntp": ["192.0.2.1", "198.51.100.1"]} and context["updated_by"] == "git:netops-configs"

    objects = _ok(admin.get(f"{BASE}/{source['id']}/objects"))["objects"]
    assert [o["git_path"] for o in objects["templates"]] == ["templates/banner.j2", "templates/cisco_ios/banner.j2"]

    # A second sync of the same commit changes nothing.
    again = _sync(admin, source["id"])["result"]["counts"]
    assert again["templates"] == {"created": 0, "updated": 0, "unchanged": 2, "removed": 0, "detached": 0}

    # Change one template, drop the playbook, add a context.
    repo.write("templates/banner.j2", "banner motd ^two^\n")
    repo.remove("playbooks/save-config.yml")
    repo.write("config_contexts/syslog.json", '{"syslog": {"host": "192.0.2.30"}}')
    second = repo.commit("update")
    counts = _sync(admin, source["id"])["result"]["counts"]
    assert counts["templates"]["updated"] == 1 and counts["templates"]["unchanged"] == 1
    assert counts["playbooks"]["removed"] == 1 and counts["config_contexts"]["created"] == 1
    banner = _ok(admin.get(f"/api/templates/{banner['id']}"))
    assert banner["content"] == "banner motd ^two^\n" and banner["git_commit"] == second
    assert not any(p["name"] == "save-config" for p in _ok(admin.get("/api/playbooks")))

    # No longer providing a content type removes its records at the next sync.
    body = {"name": "netops-configs", "remote_url": REMOTE, "provides": ["templates", "playbooks"]}
    _ok(admin.put(f"{BASE}/{source['id']}", json={**body, "credential_id": source["credential_id"]}))
    counts = _sync(admin, source["id"])["result"]["counts"]
    assert counts["config_contexts"]["removed"] == 2
    assert not [
        c for c in _ok(admin.get("/api/intended-config/contexts"))["contexts"] if c["git_source_id"] is not None
    ]


def test_owned_records_are_read_only(admin, repo):
    _seed(repo)
    source = _source(admin)
    _sync(admin, source["id"])
    template = next(t for t in _ok(admin.get("/api/templates")) if t["git_source_id"] == source["id"])
    playbook = _by_name(_ok(admin.get("/api/playbooks")), "save-config")
    context = _by_name(_ok(admin.get("/api/intended-config/contexts"))["contexts"], "ntp-servers")
    for resp in (
        admin.put(f"/api/templates/{template['id']}", json={"name": "x", "content": "y"}),
        admin.delete(f"/api/templates/{template['id']}"),
        admin.put(f"/api/playbooks/{playbook['id']}", json={"content": "- hosts: all\n"}),
        admin.delete(f"/api/playbooks/{playbook['id']}"),
        admin.put(f"/api/intended-config/contexts/{context['id']}", json={"name": "ntp-servers", "data": {}}),
        admin.delete(f"/api/intended-config/contexts/{context['id']}"),
    ):
        assert resp.status_code == 409, resp.text
        assert "netops-configs" in resp.text
    assert _ok(admin.get(f"/api/templates/{template['id']}"))["content"] == template["content"]


def test_records_written_in_plexus_are_never_overwritten(admin, repo):
    _seed(repo)
    mine = _ok(admin.post("/api/templates", json={"name": "banner", "content": "mine", "device_type": ""}), 201)
    source = _source(admin)
    out = _sync(admin, source["id"])
    assert out["ok"] is True and out["source"]["status"] == "warning"
    assert any(
        w["path"] == "templates/banner.j2" and "written in Plexus" in w["message"] for w in out["result"]["warnings"]
    )
    assert _ok(admin.get(f"/api/templates/{mine['id']}"))["content"] == "mine"
    assert out["result"]["counts"]["templates"]["created"] == 1

    # A second source cannot take over the first source's records either.
    other = _ok(admin.post(BASE, json={"name": "other", "remote_url": REMOTE}), 201)
    out = _sync(admin, other["id"])
    assert out["source"]["status"] == "warning" and out["result"]["counts"]["playbooks"]["created"] == 0
    assert any("another Git source" in w["message"] for w in out["result"]["warnings"])


def test_context_metadata_resolves_groups_and_hosts(admin, repo):
    group = int(_ok(admin.post("/api/inventory", json={"name": "branch-sites"}), 201)["id"])
    repo.write(
        "config_contexts/branch.json",
        '{"_metadata": {"group": "branch-sites", "weight": 10}, "dns": ["192.0.2.53"]}',
    )
    repo.write("config_contexts/missing.json", '{"_metadata": {"group": "nowhere"}, "a": 1}')
    repo.write("config_contexts/bad-role.json", '{"_metadata": {"role_id": 99999}, "a": 1}')
    repo.commit()
    out = _sync(admin, _source(admin, provides=["config_contexts"])["id"])
    branch = _by_name(_ok(admin.get("/api/intended-config/contexts"))["contexts"], "branch")
    assert branch["group_id"] == group and branch["weight"] == 10
    warned = {w["path"]: w["message"] for w in out["result"]["warnings"]}
    assert "does not exist" in warned["config_contexts/missing.json"]
    assert "role_id" in warned["config_contexts/bad-role.json"]


def test_failed_sync_keeps_records_and_does_not_leak_the_credential(admin, repo, tmp_path, monkeypatch):
    first = _seed(repo)
    source = _source(admin, credential_id=_service_credential())
    _sync(admin, source["id"])
    missing = (tmp_path / "missing").as_posix()
    monkeypatch.setattr(git_routes, "_remote_for", lambda s: gs.Remote("https", "127.0.0.1", missing))
    out = _sync(admin, source["id"])
    assert out["ok"] is False and out["result"] is None
    failed = out["source"]
    assert failed["status"] == "error" and failed["error"].startswith("git fetch failed")
    assert failed["last_commit"] == first and failed["object_counts"]["templates"] == 2
    token = gs.GitAuth("svc", SECRET).secrets()[-1]
    for text in (str(failed), str(_ok(admin.get(BASE))), str(asyncio.run(db.get_audit_events(limit=50)))):
        assert SECRET not in text and token not in text

    # A missing branch is reported the same way.
    monkeypatch.setattr(git_routes, "_remote_for", lambda s: gs.Remote("https", "127.0.0.1", repo.path.as_posix()))
    put = {"name": "netops-configs", "remote_url": REMOTE, "branch": "nope", "credential_id": source["credential_id"]}
    _ok(admin.put(f"{BASE}/{source['id']}", json=put))
    assert _sync(admin, source["id"])["source"]["status"] == "error"


def test_link_metadata_host_is_refused_by_the_ssrf_guard(admin, repo, monkeypatch):
    source = _source(admin)
    monkeypatch.setattr(git_routes, "_remote_for", lambda s: gs.Remote("https", "169.254.169.254", REMOTE))
    out = _sync(admin, source["id"])
    assert out["source"]["status"] == "error" and "Remote host refused" in out["source"]["error"]


def test_removed_record_still_referenced_by_a_job_is_detached(admin, repo):
    _seed(repo)
    source = _source(admin, provides=["playbooks"])
    _sync(admin, source["id"])
    playbook = _by_name(_ok(admin.get("/api/playbooks")), "save-config")

    async def add_job() -> None:
        conn = await db.get_db()
        try:
            await conn.execute("INSERT INTO jobs (playbook_id, dry_run) VALUES (?, 1)", (playbook["id"],))
            await conn.commit()
        finally:
            await conn.close()

    asyncio.run(add_job())
    repo.remove("playbooks/save-config.yml")
    repo.commit()
    counts = _sync(admin, source["id"])["result"]["counts"]["playbooks"]
    assert counts["detached"] == 1 and counts["removed"] == 0
    kept = _ok(admin.get(f"/api/playbooks/{playbook['id']}"))
    assert kept["git_source_id"] is None and kept["git_path"] == ""


def test_delete_source_removes_its_records(admin, repo):
    _seed(repo)
    source = _source(admin)
    _sync(admin, source["id"])
    out = _ok(admin.delete(f"{BASE}/{source['id']}"))
    assert out == {"ok": True, "removed": 4, "detached": 0}
    assert not [t for t in _ok(admin.get("/api/templates")) if t["name"] == "banner"]
    assert not (Path(git_routes.sources_root()) / str(source["id"])).exists()
    assert admin.get(f"{BASE}/{source['id']}").status_code == 404
    assert admin.post(f"{BASE}/{source['id']}/sync").status_code == 404


# ── API contracts, access and audit ──────────────────────────────────────────


def test_crud_contracts(admin):
    cred = _service_credential()
    made = _source(admin, credential_id=cred, provides=["playbooks", "templates"], sync_interval_minutes=30)
    assert made["provides"] == ["templates", "playbooks"] and made["sync_interval_minutes"] == 30
    assert made["updated_by"] == "admin" and made["enabled"] is True
    assert _ok(admin.get(f"{BASE}/{made['id']}")) == made
    listed = _ok(admin.get(BASE))
    assert listed["content_types"] == list(gs.CONTENT_TYPES) and [s["id"] for s in listed["sources"]] == [made["id"]]
    assert admin.post(BASE, json={"name": "NETOPS-CONFIGS", "remote_url": REMOTE}).status_code == 409
    for body in (
        {"name": "x", "remote_url": "file:///srv/repo.git"},
        {"name": "x", "remote_url": "ext::sh -c id"},
        {"name": "x", "remote_url": "https://svc:pw@git.example.com/r.git"},
        {"name": "x", "remote_url": REMOTE, "branch": "-oops"},
        {"name": "x", "remote_url": REMOTE, "provides": ["scripts"]},
        {"name": "x", "remote_url": REMOTE, "sync_interval_minutes": 2},
        {"name": " ", "remote_url": REMOTE},
        {"name": "x", "remote_url": REMOTE, "credential_id": 999999},
    ):
        assert admin.post(BASE, json=body).status_code == 400, body
    user_cred = int(asyncio.run(db.create_credential("personal", "me", encrypt("pw"))))
    assert admin.post(BASE, json={"name": "x", "remote_url": REMOTE, "credential_id": user_cred}).status_code == 400
    updated = _ok(admin.put(f"{BASE}/{made['id']}", json={"name": "renamed", "remote_url": REMOTE, "enabled": False}))
    assert updated["name"] == "renamed" and updated["enabled"] is False and updated["credential_id"] is None
    assert admin.put(f"{BASE}/999999", json={"name": "z", "remote_url": REMOTE}).status_code == 404
    assert admin.delete(f"{BASE}/999999").status_code == 404


def test_admin_only(admin):
    made = _source(admin)
    anon = TestClient(app_module.app, raise_server_exceptions=False)
    assert anon.get(BASE).status_code == 401
    user = user_client(admin, "templater", features=["templates", "playbooks", "config-drift"])
    for resp in (
        user.get(BASE),
        user.get(f"{BASE}/{made['id']}"),
        user.post(BASE, json={"name": "y", "remote_url": REMOTE}),
        user.put(f"{BASE}/{made['id']}", json={"name": "y", "remote_url": REMOTE}),
        user.delete(f"{BASE}/{made['id']}"),
        user.post(f"{BASE}/{made['id']}/sync"),
    ):
        assert resp.status_code == 403, resp.text


@needs_git
def test_writes_and_syncs_are_audited(admin, repo):
    _seed(repo)
    made = _source(admin)
    _ok(admin.put(f"{BASE}/{made['id']}", json={"name": "netops-configs", "remote_url": REMOTE}))
    _sync(admin, made["id"])
    _ok(admin.delete(f"{BASE}/{made['id']}"))
    events = asyncio.run(db.get_audit_events(limit=50, category="config"))
    actions = {e["action"] for e in events}
    assert actions >= {"git_source_create", "git_source_update", "git_source_sync", "git_source_delete"}
    sync = next(e for e in events if e["action"] == "git_source_sync")
    assert sync["user"] == "admin" and "commit=" in sync["detail"]


def test_due_sources_follow_their_interval(monkeypatch):
    now = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)

    def at(minutes_ago: int) -> str:
        return (now - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%d %H:%M:%S")

    rows = [
        {"id": 1, "enabled": True, "sync_interval_minutes": 30, "last_attempt_at": at(31)},
        {"id": 2, "enabled": True, "sync_interval_minutes": 30, "last_attempt_at": at(10)},
        {"id": 3, "enabled": False, "sync_interval_minutes": 30, "last_attempt_at": ""},
        {"id": 4, "enabled": True, "sync_interval_minutes": 0, "last_attempt_at": ""},
        {"id": 5, "enabled": True, "sync_interval_minutes": 60, "last_attempt_at": ""},
    ]
    synced: list[int] = []

    async def fake_list():
        return rows

    async def fake_sync(source_id, user=""):
        synced.append(source_id)
        return {}

    monkeypatch.setattr(db, "list_git_sources", fake_list)
    monkeypatch.setattr(git_routes, "sync_git_source", fake_sync)
    assert asyncio.run(git_routes.sync_due_sources(now)) == [1, 5]
    assert synced == [1, 5]
