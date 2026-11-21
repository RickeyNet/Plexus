"""Build and release supply chain: pinned images and actions, a checksummed
gitleaks download, a release gated on CI, and what the image leaves out.

Reads the shipped Dockerfile, compose file, .dockerignore, air-gap scripts,
frontend build config and GitHub workflows (internal security review CFG-9, CFG-11,
DEP-2, DEP-3)."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
DIGEST = re.compile(r"^[a-z0-9._/-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _yaml(path: Path) -> dict:
    return yaml.safe_load(_read(path))


# ── Images ───────────────────────────────────────────────────────────────────


def test_dockerfile_base_images_are_pinned_by_digest():
    images = re.findall(r"^FROM\s+(\S+)", _read(ROOT / "Dockerfile"), flags=re.M)
    assert len(images) == 2
    for image in images:
        assert DIGEST.match(image), image


def test_compose_service_images_are_pinned_by_digest():
    services = _yaml(ROOT / "docker-compose.yml")["services"]
    for name in ("postgres", "nginx"):
        assert DIGEST.match(services[name]["image"]), name
    # nginx names a version, not a floating "alpine" tag.
    tag = services["nginx"]["image"].split("@", 1)[0].split(":", 1)[1]
    assert re.match(r"^\d+\.\d+\.\d+-alpine$", tag), tag


def test_ci_service_images_are_pinned_by_digest():
    jobs = _yaml(WORKFLOWS / "ci.yml")["jobs"]
    images = [
        (job_name, service["image"])
        for job_name, job in jobs.items()
        for service in (job.get("services") or {}).values()
    ]
    assert images
    for job_name, image in images:
        assert DIGEST.match(image), f"{job_name}: {image}"


def test_image_installs_python_packages_only_from_hashed_pins():
    """Every pip install of the Dockerfile, pip's own upgrade included."""
    dockerfile = _read(ROOT / "Dockerfile")
    installs = re.findall(r"pip install[^\n&;]*", dockerfile)
    assert installs
    for install in installs:
        assert "--require-hashes" in install, install
    pin = [
        line
        for line in _read(ROOT / "requirements-pip.txt").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    assert re.fullmatch(r"pip==\d+(\.\d+)+ \\", pin[0]), pin[0]
    assert len(pin) > 1
    for line in pin[1:]:
        assert re.fullmatch(r"\s+--hash=sha256:[0-9a-f]{64}( \\)?", line), line


def test_airgap_bundle_saves_the_compose_images_under_their_tag():
    """A loaded tar has no registry digest, so the offline host must name
    the images by tag: bundle.sh writes an override and install.sh enables
    it through COMPOSE_FILE."""
    bundle = _read(ROOT / "deploy" / "airgap" / "bundle.sh")
    install = _read(ROOT / "deploy" / "airgap" / "install.sh")
    assert "compose_image postgres" in bundle and "compose_image nginx" in bundle
    assert 'POSTGRES_TAG="${POSTGRES_IMAGE%@*}"' in bundle
    assert 'docker save -o "$OUT_DIR/images/postgres.tar" "$POSTGRES_TAG"' in bundle
    assert 'docker save -o "$OUT_DIR/images/nginx.tar"    "$NGINX_TAG"' in bundle
    assert "docker-compose.airgap.yml" in bundle
    assert "set_env COMPOSE_FILE docker-compose.yml:docker-compose.airgap.yml" in install
    # No hard-coded floating defaults left behind.
    assert "nginx:alpine" not in bundle


def test_dependabot_updates_dockerfile_and_compose_images():
    ecosystems = {u["package-ecosystem"] for u in _yaml(ROOT / ".github" / "dependabot.yml")["updates"]}
    assert {"docker", "docker-compose", "github-actions"} <= ecosystems


# ── What the image contains ──────────────────────────────────────────────────


def _dockerignore_excludes(path: str) -> bool:
    """Last matching pattern wins; a match on a parent excludes the path
    (the same reading as tests/test_help_docs.py)."""
    patterns = []
    for line in _read(ROOT / ".dockerignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            patterns.append((line.startswith("!"), line.lstrip("!").rstrip("/")))
    target = PurePosixPath(path)
    state = False
    for negated, pattern in patterns:
        if any(c.full_match(pattern) for c in [target, *target.parents[:-1]]):
            state = not negated
    return state


def test_dockerignore_excludes_sqlite_sidecars_and_auth_backups():
    for path in (
        "netcontrol.db-wal",
        "netcontrol.db-shm",
        "netcontrol.db-journal",
        "routes/netcontrol.db-wal",
        "routes/auth.json",
        "routes/auth.json.bak",
        "auth.json",
        "state.bak",
        "netcontrol/settings.bak",
        "netcontrol.migrate.lock",
    ):
        assert _dockerignore_excludes(path), path
    for path in ("netcontrol/app.py", "routes/database.py", "Dockerfile", "netcontrol/static/frontend/src/main.tsx"):
        assert not _dockerignore_excludes(path), path


def test_runtime_image_keeps_only_the_built_frontend():
    dockerfile = _read(ROOT / "Dockerfile")
    prune = "find /app/netcontrol/static/frontend -mindepth 1 -maxdepth 1 ! -name dist -exec rm -rf {} +"
    assert prune in dockerfile
    # After the source copy, before the built bundle is copied in.
    assert dockerfile.index("COPY . .") < dockerfile.index(prune)
    assert dockerfile.index(prune) < dockerfile.index("COPY --from=frontend-build")


def test_production_build_has_no_source_maps_and_ships_the_embed_echarts():
    from netcontrol.routes.graph_export import ECHARTS_SCRIPT_SRC

    config = _read(ROOT / "netcontrol" / "static" / "frontend" / "vite.config.ts")
    assert re.search(r"^\s*sourcemap:\s*false,", config, flags=re.M)
    assert f"'{ECHARTS_SCRIPT_SRC.lstrip('/')}'" in config


# ── Workflows ────────────────────────────────────────────────────────────────


def _workflow_files() -> list[Path]:
    return sorted(WORKFLOWS.glob("*.yml"))


def test_every_action_is_pinned_to_a_commit():
    uses = []
    for path in _workflow_files():
        uses += [
            (path.name, line.strip())
            for line in _read(path).splitlines()
            if line.strip().startswith(("uses:", "- uses:"))
        ]
    assert uses
    for name, line in uses:
        assert re.search(r"uses: [\w.-]+/[\w.-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+$", line), f"{name}: {line}"


def test_gitleaks_download_is_checksummed_before_extracting():
    ci = _yaml(WORKFLOWS / "ci.yml")
    step = next(s for s in ci["jobs"]["secret-scan"]["steps"] if s.get("name") == "Secret scan (gitleaks)")
    assert re.fullmatch(r"[0-9a-f]{64}", step["env"]["GITLEAKS_SHA256"])
    run = step["run"]
    assert "| tar" not in run
    assert run.index("sha256sum -c") < run.index("tar -xzf")


def test_release_publishes_only_after_ci_succeeded():
    release = _yaml(WORKFLOWS / "release.yml")
    jobs = release["jobs"]
    gate = jobs["ci-gate"]
    assert gate["permissions"] == {"actions": "read"}
    script = gate["steps"][0]["run"]
    assert "actions/workflows/ci.yml/runs?head_sha=${SHA}" in script
    assert gate["steps"][0]["env"]["SHA"] == "${{ github.sha }}"
    for name, job in jobs.items():
        if name != "ci-gate":
            needs = job.get("needs")
            assert needs == "ci-gate" or (isinstance(needs, list) and "ci-gate" in needs), name


def test_manual_release_run_builds_only_the_commit_its_tag_names():
    steps = _yaml(WORKFLOWS / "release.yml")["jobs"]["validate-and-publish"]["steps"]
    names = [step.get("name") for step in steps]
    resolve = steps[names.index("Resolve release tag")]["run"]
    assert 'git ls-remote origin "refs/tags/${raw}" "refs/tags/${raw}^{}"' in resolve
    assert '[ "$tag_sha" != "$GITHUB_SHA" ]' in resolve
    # Checked before anything is built or pushed.
    assert names.index("Resolve release tag") < names.index("Build image for vulnerability scan (amd64)")
