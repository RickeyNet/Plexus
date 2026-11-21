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
