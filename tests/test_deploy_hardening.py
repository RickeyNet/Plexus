"""Deployment defaults: the client address, request sizes and the first login.

Reads the shipped deploy files (nginx config, compose files, setup scripts
and their docs) and checks the settings that keep per-IP limits, body limits
and the bootstrap admin safe."""

from __future__ import annotations

import re
from pathlib import Path

import yaml
from netcontrol.body_limit import MIB, BodyLimitMiddleware, default_path_limits

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"
NGINX_CONF = DEPLOY / "nginx.conf"


def _text_files(*paths: Path) -> list[Path]:
    out: list[Path] = []
    for path in paths:
        if path.is_dir():
            out.extend(p for p in sorted(path.rglob("*")) if p.is_file() and p.suffix != ".pem")
        elif path.is_file():
            out.append(path)
    return out


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _nginx(path: Path) -> str:
    """An nginx config without its comments."""
    return re.sub(r"#.*", "", _read(path))


def _nginx_configs() -> list[Path]:
    return [p for p in _text_files(DEPLOY) if p.suffix == ".conf" or "nginx" in p.name]


def _locations(conf: str) -> dict[str, str]:
    """``location`` header (``= /path``, ``~ regex``, ``/``) -> block body."""
    blocks: dict[str, str] = {}
    for match in re.finditer(r"location\s+([^{]+?)\s*\{", conf):
        depth, i = 1, match.end()
        while depth:
            depth += {"{": 1, "}": -1}.get(conf[i], 0)
            i += 1
        blocks[match.group(1).strip()] = conf[match.end() : i - 1]
    return blocks


def _size(value: str) -> int:
    units = {"k": 1024, "m": MIB, "g": 1024 * MIB}
    value = value.strip().lower()
    return int(value[:-1]) * units[value[-1]] if value[-1] in units else int(value)


def _body_limit(block: str) -> int | None:
    match = re.search(r"client_max_body_size\s+(\S+);", block)
    return _size(match.group(1)) if match else None


# ── X-Forwarded-For ──────────────────────────────────────────────────────────


def test_no_nginx_config_appends_to_client_x_forwarded_for():
    configs = _nginx_configs()
    assert NGINX_CONF in configs
    docs = _text_files(ROOT / "docs", DEPLOY, ROOT / "README.md", ROOT / "DEVSETUP.md")
    for path in set(configs) | {p for p in docs if p.suffix == ".md"}:
        assert "$proxy_add_x_forwarded_for" not in _read(path), path


def test_every_proxied_location_overwrites_x_forwarded_for():
    for path in _nginx_configs():
        for header, block in _locations(_nginx(path)).items():
            if "proxy_pass" not in block:
                continue
            assert re.search(r"proxy_set_header\s+X-Forwarded-For\s+\$remote_addr;", block), (path, header)


def _compose_files() -> list[Path]:
    return sorted(ROOT.glob("docker-compose*.yml")) + sorted(DEPLOY.rglob("docker-compose*.yml"))


def test_no_compose_file_trusts_forwarded_headers_from_everyone():
    files = _compose_files()
    assert files
    pattern = re.compile(r"FORWARDED_ALLOW_IPS\s*[:=]\s*[\"']?\*")
    for path in [*files, ROOT / ".env.example"]:
        assert not pattern.search(_read(path)), path


def _default(value: str) -> str:
    """``${VAR:-default}`` -> ``default``."""
    match = re.fullmatch(r"\$\{\w+:-([^}]*)\}", value.strip())
    return match.group(1) if match else value


def test_compose_trusts_exactly_the_nginx_address():
    compose = yaml.safe_load(_read(ROOT / "docker-compose.yml"))
    services = compose["services"]
    trusted = _default(str(services["plexus"]["environment"]["FORWARDED_ALLOW_IPS"]))
    nginx_ip = _default(services["nginx"]["networks"]["plexus"]["ipv4_address"])
    subnet = _default(compose["networks"]["plexus"]["ipam"]["config"][0]["subnet"])
    assert trusted == nginx_ip

    import ipaddress

    assert ipaddress.ip_address(nginx_ip) in ipaddress.ip_network(subnet)
    # The Docker gateway (.1) carries host-loopback traffic to the app; it
    # must not be the trusted address.
    assert ipaddress.ip_address(nginx_ip) != next(ipaddress.ip_network(subnet).hosts())


# ── Body sizes ───────────────────────────────────────────────────────────────


def test_nginx_server_body_limit_is_small():
    conf = _nginx(NGINX_CONF)
    server_level = re.sub(r"location\s+[^{]+\{[^}]*\}", "", conf)
    limit = _body_limit(server_level)
    assert limit is not None and limit <= 16 * MIB
    assert limit >= BodyLimitMiddleware(None).default_limit
    assert "proxy_request_buffering off" not in _locations(conf)["/"]
    assert "client_body_timeout" not in _locations(conf)["/"]


# ── Connections per address ──────────────────────────────────────────────────


def test_nginx_caps_connections_per_client_address():
    conf = _nginx(NGINX_CONF)
    zone = re.search(r"limit_conn_zone\s+\$binary_remote_addr\s+zone=(\w+):(\S+);", conf)
    assert zone, "limit_conn_zone keyed on the client address is missing"
    server_level = re.sub(r"location\s+[^{]+\{[^}]*\}", "", conf)
    limit = re.search(rf"limit_conn\s+{zone.group(1)}\s+(\d+);", server_level)
    assert limit, "limit_conn must be set at server level so every location (/ws/ and SSE too) is covered"
    # Several tabs with streams and sockets fit; hundreds from one address do not.
    assert 32 <= int(limit.group(1)) <= 200
    assert re.search(r"limit_conn_status\s+429;", server_level)
    # No location switches the limit off.
    for header, block in _locations(conf).items():
        assert "limit_conn " not in block, header


def test_nginx_limits_the_password_sign_in_request_rate():
    conf = _nginx(NGINX_CONF)
    zone = re.search(r"limit_req_zone\s+\$binary_remote_addr\s+zone=(\w+):\S+\s+rate=(\d+)r/m;", conf)
    assert zone, "limit_req_zone keyed on the client address is missing"
    assert 10 <= int(zone.group(2)) <= 120
    limited = [
        header
        for header, block in _locations(conf).items()
        if re.search(rf"limit_req\s+zone={zone.group(1)}\b", block) and re.search(r"limit_req_status\s+429;", block)
    ]
    assert len(limited) == 1, limited
    modifier, _, pattern = limited[0].partition(" ")
    assert modifier == "~"
    # Exactly the two routes that hash a password for an anonymous caller.
    for path in ("/api/auth/login", "/api/auth/register"):
        assert re.search(pattern, path), path
    for path in ("/api/auth/status", "/api/auth/login/x", "/api/auth/oidc/login", "/x/api/auth/login"):
        assert not re.search(pattern, path), path


def test_nginx_upload_locations_match_the_app_allowlist():
    locations = _locations(_nginx(NGINX_CONF))
    nginx_uploads: dict[str, int] = {}
    for header, block in locations.items():
        limit = _body_limit(block)
        if limit is None:
            continue
        modifier, _, target = header.partition(" ")
        if modifier == "=":
            nginx_uploads[target.strip()] = limit
        elif modifier == "~":
            nginx_uploads[target.strip().removeprefix("^").removesuffix("$")] = limit
        else:
            raise AssertionError(f"large body limit on a prefix location: {header}")

    app_uploads = {pattern.pattern: limit for pattern, limit in default_path_limits()}
    assert set(app_uploads) == set(nginx_uploads)
    for pattern, app_limit in app_uploads.items():
        assert nginx_uploads[pattern] >= app_limit, pattern


# ── First login ──────────────────────────────────────────────────────────────

_OLD_DEFAULT = re.compile(r"PASSWORD\s*=\s*netcontrol\b|admin`?\s*/\s*`?netcontrol\b")


def test_no_shipped_default_admin_password():
    paths = _text_files(DEPLOY, ROOT / "README.md", *_compose_files())
    for path in paths:
        assert not _OLD_DEFAULT.search(_read(path)), path
    # .env.example names the opt-in dev login in a comment, but ships the
    # real setting empty (random password on first boot).
    assert re.search(r"^PLEXUS_INITIAL_ADMIN_PASSWORD=$", _read(ROOT / ".env.example"), re.M)


def test_setup_generates_the_first_login_password():
    setup = _read(DEPLOY / "setup.sh")
    assert re.search(r"ADMIN_PASSWORD=\$\(python3 -c \"import secrets; print\(secrets\.token_urlsafe", setup)
    assert "PLEXUS_INITIAL_ADMIN_PASSWORD=${ADMIN_PASSWORD}" in setup


# ── Server API token (opt-in) ────────────────────────────────────────────────


def test_setup_leaves_the_api_token_empty_unless_asked():
    setup = _read(DEPLOY / "setup.sh")
    # The token is generated only inside the opt-in branch.
    assert re.search(r'API_TOKEN=""\n\s+if \[ "\$\{WITH_API_TOKEN\}" = "true" \]; then\n\s+API_TOKEN=\$\(', setup)
    assert re.search(r"^WITH_API_TOKEN=false$", setup, re.M)
    assert "--with-api-token) WITH_API_TOKEN=true" in setup
    assert "PLEXUS_ENABLE_API_TOKEN" in setup
    assert "APP_API_TOKEN=${API_TOKEN}" in setup
    assert re.search(r"^APP_API_TOKEN=$", _read(ROOT / ".env.example"), re.M)


def test_installers_pass_the_api_token_opt_in_through():
    bootstrap = _read(DEPLOY / "bootstrap.sh")
    assert "SETUP_ARGS+=(--with-api-token)" in bootstrap
    assert 'bash deploy/setup.sh ${SETUP_ARGS[@]+"${SETUP_ARGS[@]}"}' in bootstrap
    assert "PLEXUS_ENABLE_API_TOKEN" in _read(DEPLOY / "airgap" / "install.sh")


def test_docs_do_not_promise_an_auto_generated_api_token():
    for path in _text_files(DEPLOY, ROOT / "README.md", ROOT / "DEVSETUP.md", ROOT / "docs"):
        if path.suffix != ".md" or "superpowers" in path.parts:
            continue
        assert "(auto-generated) | Token for API" not in _read(path), path


# ── Host updater (runs as root) ──────────────────────────────────────────────

UPDATER = DEPLOY / "plexus-updater.sh"
UPDATER_UNIT = DEPLOY / "systemd" / "plexus-updater.service"


def test_updater_writes_only_into_the_status_dir():
    script = _read(UPDATER)
    assert 'STATUS_DIR="${INSTALL_DIR}/state/update-status"' in script
    for name, file in [
        ("INPROGRESS", "request.inprogress.json"),
        ("RESULT", "result.json"),
        ("LOG_FILE", "upgrade.log"),
        ("ROLLBACK_JSON", "rollback.json"),
        ("AGENT_MARKER", ".agent-installed"),
    ]:
        assert f'{name}="${{STATUS_DIR}}/{file}"' in script, name
    # The request dir is used for request.json and legacy clean-up only.
    uses = re.findall(r"\$\{UPDATES_DIR[:?]*\}/?([\w.${}\[\]]*)", script)
    assert set(uses) <= {"request.json", "${name}", ""}, uses
    assert 'mv -f "${REQUEST}"' not in script
    # The status dir is root-owned and refused when it is a symlink.
    assert "install -d -m 0755 -o root -g root" in script
    assert '-L "${STATUS_DIR}"' in script


def test_updater_claims_the_request_without_following_links():
    script = _read(UPDATER)
    claim = script[script.index("claim_request() {") :]
    claim = claim[: claim.index("\nPY\n}")]
    assert "O_NOFOLLOW" in claim
    assert "follow_symlinks=False" in claim
    assert "S_ISREG" in claim
    assert "st_nlink != 1" in claim
    assert "dir_fd=dfd" in claim
    assert "os.path.realpath(updates) != expected" in claim
    assert "O_NONBLOCK" in claim
    # A rejected request is reported, not run.
    assert re.search(r'if ! CLAIM_MSG="\$\(claim_request\)"; then\n(.*\n){0,4}\s+exit 0', script)
    # A dangling symlink still counts as a request (and is rejected).
    assert '[[ ! -e "${REQUEST}" && ! -L "${REQUEST}" ]]' in script


def test_updater_unit_is_hardened_without_blocking_git_or_docker():
    unit = _read(UPDATER_UNIT)
    opts = dict(line.split("=", 1) for line in unit.splitlines() if "=" in line and not line.lstrip().startswith("#"))
    assert opts["NoNewPrivileges"] == "yes"
    assert opts["PrivateTmp"] == "yes"
    assert opts["ProtectSystem"] in {"full", "strict"}
    assert opts["ProtectHome"] == "read-only"
    assert "@INSTALL_DIR@" in opts["ReadWritePaths"]
    assert "@OWNER_HOME@" in opts["ReadWritePaths"]
    # runuser needs setuid/setgid; the owner's home holds ~/.docker.
    for forbidden in ("CapabilityBoundingSet", "PrivateUsers", "User", "DynamicUser"):
        assert forbidden not in opts, forbidden
    assert opts["ProtectHome"] not in {"yes", "tmpfs"}
    bootstrap = _read(DEPLOY / "bootstrap.sh")
    assert "s|@OWNER_HOME@|${OWNER_HOME}|g" in bootstrap
    assert "install -d -m 0755 -o root -g root state/update-status" in bootstrap
    assert "touch state/update-status/.agent-installed" in bootstrap


def test_compose_mounts_the_update_status_read_only():
    plexus = yaml.safe_load(_read(ROOT / "docker-compose.yml"))["services"]["plexus"]
    volumes = plexus["volumes"]
    assert "./state/update-status:/app/state/update-status:ro" in volumes
    assert "./state/updates:/app/state/updates" in volumes
    assert plexus["environment"]["PLEXUS_UPDATE_STATUS_DIR"] == "/app/state/update-status"
    # The entrypoint must not chown (write) the read-only status mount.
    assert "update-status" not in _read(DEPLOY / "docker-entrypoint.sh")


def test_updater_git_ref_cannot_start_with_a_dash():
    """The ref reaches ``git checkout`` on the host as root; the app refuses
    a leading ``-`` (admin_updates._REF_RE) and the host check must too."""
    script = _read(UPDATER)
    match = re.search(r'if \[\[ ! "\$\{REF\}" =~ (\S+) \]\]; then', script)
    assert match, "git ref check not found in plexus-updater.sh"
    pattern = re.compile(match.group(1))
    for ref in ("main", "release/1.2", "v1.2.3", "feature/a-b", "0a1b2c3"):
        assert pattern.fullmatch(ref), ref
    for ref in ("-f", "--force", "-", "", "a b", "a;b", "x" * 129):
        assert not pattern.fullmatch(ref), ref
