"""Git data sources: remote URL and branch rules, the ``git`` CLI runner and
the files a checkout provides.

Nothing here touches the database. ``netcontrol.routes.git_sources`` calls
``fetch_checkout`` (blocking; run it in a thread) to bring a working copy to
the branch head, then ``collect_items`` to read the files under the content
type directories, and writes the records through ``routes.db.git_sources``.

Security rules:

- Only ``https://`` and ``ssh://`` remotes (or scp-like ``user@host:path``)
  are accepted; ``file://``, ``ext::`` and every other transport are
  refused, and ``GIT_ALLOW_PROTOCOL`` limits git itself to ``https:ssh``.
  A URL with a user name and password in it is refused, so the stored URL
  never holds a secret.
- ``git`` runs from an argument list (no shell) with a timeout, no terminal
  prompt, no system or global git config and no credential helper. HTTPS credentials go in
  an ``http.extraHeader`` passed through ``GIT_CONFIG_*`` environment
  variables, an SSH key in a private temporary file that is removed after
  the command; neither is ever on the command line, in the URL or in an
  error message (``scrub`` masks them).
- Symbolic links in the checkout are written as plain files
  (``core.symlinks=false``) and skipped when reading, so a repository cannot
  point a file at something on the server.

See ``docs/git-data-sources.md``.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shlex
import shutil
import stat
import subprocess  # nosec B404 - git runs from an argument list, never a shell
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from netcontrol.custom_fields import CustomFieldError, clean_name, clean_text
from netcontrol.intended_config import (
    clean_context_data,
    clean_description,
    clean_device_type,
    clean_name_value,
    clean_weight,
)

# The content types a source can provide, each read from the directory of
# the same name at the top of the repository.
CONTENT_TYPES: tuple[str, ...] = ("templates", "playbooks", "config_contexts")
STATUSES: tuple[str, ...] = ("never", "syncing", "ok", "warning", "error")

NAME_MAX = 100
URL_MAX = 2048
BRANCH_MAX = 200
INTERVAL_MAX_MINUTES = 7 * 24 * 60
INTERVAL_MIN_MINUTES = 5
GIT_TIMEOUT_SECONDS = 120
# Largest file read from a checkout; bigger ones are skipped with a warning.
FILE_MAX_BYTES = 262_144
# Most files read per content type; the rest are skipped with a warning.
FILES_MAX = 2000
# Protocols git itself may use (GIT_ALLOW_PROTOCOL).
ALLOWED_PROTOCOLS = "https:ssh"

TEMPLATE_EXTENSIONS = (".j2", ".jinja", ".jinja2", ".txt", ".cfg", ".conf", ".tmpl")
PLAYBOOK_EXTENSIONS = (".yml", ".yaml")
CONTEXT_EXTENSIONS = (".json", ".yml", ".yaml")
CONTEXT_METADATA_KEY = "_metadata"

_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_SCP_RE = re.compile(r"^(?P<user>[A-Za-z0-9._-]+)@(?P<host>[A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\]):(?P<path>[^/].*|/.+)$")
_SCHEME_RE = re.compile(r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://")
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$|^[0-9A-Fa-f:.]+$")
_DEVICE_TYPE_RE = re.compile(r"^[a-z0-9_]{1,64}$")
_URL_USERINFO_RE = re.compile(r"(?i)\b(https?|ssh)://[^/@\s]+@")
_SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")


class GitSourceError(Exception):
    """A sync or validation failure whose message is safe to show (never
    holds a credential)."""


@dataclass(frozen=True)
class Remote:
    """A validated remote: ``kind`` ``https`` or ``ssh``, the host and the
    URL exactly as stored."""

    kind: str
    host: str
    url: str


@dataclass
class GitAuth:
    """Credentials for one git command. ``username`` and ``password`` (an
    access token for most hosts) for HTTPS; ``private_key`` for SSH."""

    username: str = ""
    password: str = field(default="", repr=False)
    private_key: str = field(default="", repr=False)

    def secrets(self) -> list[str]:
        out = [s for s in (self.password, self.private_key) if s]
        if self.password:
            out.append(_basic_token(self.username, self.password))
        return out


@dataclass
class Item:
    """One record a checkout provides: its content type, the repository path
    it came from and the values to store."""

    kind: str
    path: str
    values: dict


@dataclass
class Collected:
    """``collect_items`` result: the records found per content type and a
    warning for each file that was skipped."""

    items: dict[str, list[Item]] = field(default_factory=dict)
    warnings: list[dict] = field(default_factory=list)

    def warn(self, path: str, message: str) -> None:
        self.warnings.append({"path": path, "message": message})


# ── Validation ───────────────────────────────────────────────────────────────


def _clean(fn, raw):
    try:
        return fn(raw)
    except CustomFieldError as exc:
        raise GitSourceError(str(exc)) from exc


def clean_source_name(raw: object) -> str:
    return _clean(lambda v: clean_name(v, "Name", NAME_MAX), raw)


def parse_remote(raw: object) -> Remote:
    """The remote URL trimmed and checked: ``https://host/path``,
    ``ssh://[user@]host[:port]/path`` or ``user@host:path``. Everything else
    (``file://``, ``ext::``, ``git://``, ``http://``, a local path) is
    refused, as is a password in the URL."""
    url = raw.strip() if isinstance(raw, str) else ""
    if not url:
        raise GitSourceError("Remote URL must not be empty.")
    if len(url) > URL_MAX:
        raise GitSourceError(f"Remote URL must be at most {URL_MAX} characters.")
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in url):
        raise GitSourceError("Remote URL must not contain spaces or control characters.")
    if url.startswith("-"):
        raise GitSourceError("Remote URL must not start with '-'.")
    match = _SCHEME_RE.match(url)
    if match is None:
        if "::" in url:
            raise GitSourceError("Remote helper transports (such as ext::) are not allowed.")
        scp = _SCP_RE.match(url)
        if scp is None:
            raise GitSourceError("Remote URL must be https://…, ssh://… or user@host:path.")
        host = scp.group("host").strip("[]")
        if scp.group("path").startswith("-"):
            raise GitSourceError("Remote path must not start with '-'.")
        return Remote("ssh", host, url)
    scheme = match.group("scheme").lower()
    if scheme not in ("https", "ssh"):
        raise GitSourceError(f"Remote scheme '{scheme}' is not allowed; use https or ssh.")
    parts = urlsplit(url)
    try:
        host = parts.hostname or ""
        parts.port  # noqa: B018 - raises ValueError on a bad port
    except ValueError as exc:
        raise GitSourceError("Remote URL has an invalid port.") from exc
    if not host or not _HOST_RE.match(host) or host.startswith("-"):
        raise GitSourceError("Remote URL must name a host.")
    if parts.password is not None or (scheme == "https" and parts.username is not None):
        raise GitSourceError("Remote URL must not contain credentials; choose a credential instead.")
    if not parts.path or parts.path == "/":
        raise GitSourceError("Remote URL must name a repository path.")
    return Remote(scheme, host, url)


def clean_branch(raw: object) -> str:
    """A branch name: letters, digits, ``. _ / -``, not starting with ``-``
    or ``.``, without ``..``, ``//``, a trailing ``/`` or ``.lock``."""
    branch = raw.strip() if isinstance(raw, str) else ""
    if not branch:
        raise GitSourceError("Branch must not be empty.")
    if (
        len(branch) > BRANCH_MAX
        or not _BRANCH_RE.match(branch)
        or ".." in branch
        or "//" in branch
        or "/." in branch
        or branch.endswith(("/", ".lock", "."))
    ):
        raise GitSourceError("Branch is not a valid branch name.")
    return branch


def clean_provides(raw: object) -> list[str]:
    """The content types, each at most once, in ``CONTENT_TYPES`` order."""
    if not isinstance(raw, list) or not raw:
        raise GitSourceError(f"Provides must list at least one of: {', '.join(CONTENT_TYPES)}.")
    unknown = [v for v in raw if v not in CONTENT_TYPES]
    if unknown:
        raise GitSourceError(f"Unknown content type '{unknown[0]}'; use {', '.join(CONTENT_TYPES)}.")
    return [t for t in CONTENT_TYPES if t in raw]


def clean_interval(raw: object) -> int:
    """``0`` (sync only on demand) or ``INTERVAL_MIN_MINUTES`` to
    ``INTERVAL_MAX_MINUTES``."""
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise GitSourceError("Sync interval must be a whole number of minutes.")
    if raw != 0 and not INTERVAL_MIN_MINUTES <= raw <= INTERVAL_MAX_MINUTES:
        raise GitSourceError(
            f"Sync interval must be 0 (on demand only) or {INTERVAL_MIN_MINUTES} to {INTERVAL_MAX_MINUTES} minutes."
        )
    return raw


# ── git runner ───────────────────────────────────────────────────────────────


def _basic_token(username: str, password: str) -> str:
    return base64.b64encode(f"{username}:{password}".encode()).decode("ascii")


def scrub(text: str, secrets: Iterable[str] = ()) -> str:
    """``text`` with every secret and any URL user info replaced by ``***``."""
    out = text or ""
    for secret in sorted({s for s in secrets if s}, key=len, reverse=True):
        out = out.replace(secret, "***")
    return _URL_USERINFO_RE.sub(lambda m: f"{m.group(1)}://***@", out)


def git_binary() -> str:
    path = shutil.which("git")
    if not path:
        raise GitSourceError("git is not installed on the Plexus server.")
    return path


def _env(auth: GitAuth | None, ssh_command: str | None) -> dict[str, str]:
    """The environment of a git command: the server's, without any ``GIT_*``
    variable it had, plus the rules in the module docstring."""
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    config: list[tuple[str, str]] = [
        ("credential.helper", ""),
        ("core.symlinks", "false"),
        ("core.fsmonitor", "false"),
        ("core.hooksPath", os.devnull),
        ("advice.detachedHead", "false"),
    ]
    if auth is not None and auth.password:
        config.append(("http.extraHeader", f"Authorization: Basic {_basic_token(auth.username, auth.password)}"))
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "",
            "SSH_ASKPASS": "",
            "GCM_INTERACTIVE": "never",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_ALLOW_PROTOCOL": ALLOWED_PROTOCOLS,
            "GIT_CONFIG_COUNT": str(len(config)),
            "LC_ALL": "C",
        }
    )
    for i, (key, value) in enumerate(config):
        env[f"GIT_CONFIG_KEY_{i}"] = key
        env[f"GIT_CONFIG_VALUE_{i}"] = value
    if ssh_command:
        env["GIT_SSH_COMMAND"] = ssh_command
    return env


def run_git(
    args: list[str],
    *,
    env: dict[str, str],
    secrets: Iterable[str] = (),
    timeout: int = GIT_TIMEOUT_SECONDS,
) -> str:
    """Run ``git <args>``; its stdout. ``GitSourceError`` (scrubbed) when it
    fails or runs longer than ``timeout`` seconds."""
    command = args[2:] if args[:1] == ["-C"] else args
    what = command[0] if command else "git"
    try:
        proc = subprocess.run(  # nosec B603 - argument list, no shell; arguments validated by the caller
            [git_binary(), *args],
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise GitSourceError(f"git {what} timed out after {timeout} seconds.") from exc
    except OSError as exc:
        raise GitSourceError(f"git could not be run: {type(exc).__name__}.") from exc
    if proc.returncode != 0:
        detail = scrub((proc.stderr or proc.stdout or "").strip(), secrets)
        raise GitSourceError(f"git {what} failed: {detail[-800:] or f'exit code {proc.returncode}'}")
    return proc.stdout


def _private_file(directory: str, name: str, text: str) -> str:
    path = os.path.join(directory, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text if text.endswith("\n") else text + "\n")
    return path


def _ssh_command(key_file: str | None, known_hosts: str) -> str:
    parts = ["ssh"]
    if key_file:
        parts += ["-i", key_file, "-o", "IdentitiesOnly=yes"]
    parts += [
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
    ]
    # GIT_SSH_COMMAND is run by a shell; every part is quoted.
    return " ".join(shlex.quote(p.replace("\\", "/")) for p in parts)


def fetch_checkout(workdir: str, remote: Remote, branch: str, auth: GitAuth | None, known_hosts: str) -> str:
    """Bring ``workdir`` to the head of ``branch`` of the remote (a shallow
    fetch, a forced checkout and a clean) and return its commit SHA."""
    os.makedirs(workdir, exist_ok=True)
    secrets = auth.secrets() if auth is not None else []
    key_dir = None
    try:
        ssh_command = None
        if remote.kind == "ssh":
            key_file = None
            if auth is not None and auth.private_key:
                key_dir = tempfile.mkdtemp(prefix="plexus-git-")
                key_file = _private_file(key_dir, "id_key", auth.private_key)
            ssh_command = _ssh_command(key_file, known_hosts)
        env = _env(auth if remote.kind == "https" else None, ssh_command)
        if not os.path.isdir(os.path.join(workdir, ".git")):
            run_git(["init", "-q", workdir], env=env, secrets=secrets)
        git = ["-C", workdir]
        run_git(
            [
                *git,
                "fetch",
                "-q",
                "--depth=1",
                "--no-tags",
                "--no-recurse-submodules",
                "--",
                remote.url,
                f"refs/heads/{branch}",
            ],
            env=env,
            secrets=secrets,
        )
        run_git([*git, "checkout", "-q", "--force", "--detach", "FETCH_HEAD"], env=env, secrets=secrets)
        run_git([*git, "clean", "-q", "-ffdx"], env=env, secrets=secrets)
        sha = run_git([*git, "rev-parse", "HEAD"], env=env, secrets=secrets).strip()
    finally:
        if key_dir is not None:
            shutil.rmtree(key_dir, ignore_errors=True)
    if not _SHA_RE.match(sha):
        raise GitSourceError("git did not report a commit for the branch head.")
    return sha


def remove_workdir(path: str) -> None:
    """Delete a working copy, including git's read-only object files."""

    def _retry(func, target, _exc) -> None:
        try:
            os.chmod(target, stat.S_IWRITE | stat.S_IREAD)
            func(target)
        except OSError:
            pass

    if os.path.isdir(path):
        shutil.rmtree(path, onexc=_retry)


# ── Reading a checkout ───────────────────────────────────────────────────────


def _files(root: Path, top: str, extensions: tuple[str, ...], out: Collected, *, depth: int) -> list[tuple[str, Path]]:
    """``(repository path, file)`` of the regular files under ``top`` with
    one of the extensions, at most ``depth`` directories down, by path.
    Symbolic links, hidden names, large files and other extensions are
    skipped (the last silently)."""
    base = root / top
    if not base.is_dir() or base.is_symlink():
        return []
    found: list[tuple[str, Path]] = []
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        here = Path(dirpath)
        level = len(here.relative_to(base).parts)
        dirnames[:] = sorted(d for d in dirnames if not d.startswith(".") and not (here / d).is_symlink())
        for name in sorted(filenames):
            path = here / name
            rel = path.relative_to(root).as_posix()
            if name.startswith(".") or not name.lower().endswith(extensions):
                continue
            if level > depth:
                out.warn(rel, f"Skipped: files in {top}/ may be at most {depth} folder(s) deep.")
                continue
            if path.is_symlink() or not path.is_file():
                out.warn(rel, "Skipped: symbolic links are not imported.")
                continue
            if path.stat().st_size > FILE_MAX_BYTES:
                out.warn(rel, f"Skipped: larger than {FILE_MAX_BYTES} bytes.")
                continue
            found.append((rel, path))
    found.sort(key=lambda f: f[0])
    if len(found) > FILES_MAX:
        for rel, _ in found[FILES_MAX:]:
            out.warn(rel, f"Skipped: more than {FILES_MAX} files in {top}/.")
        found = found[:FILES_MAX]
    return found


def _read_text(path: Path, rel: str, out: Collected) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError, OSError:
        out.warn(rel, "Skipped: not UTF-8 text.")
        return None


def _stem(name: str) -> str:
    return name.rsplit(".", 1)[0]


def _template_item(rel: str, path: Path, text: str, out: Collected) -> Item | None:
    """``templates/<name>.<ext>`` (any driver) or
    ``templates/<device_type>/<name>.<ext>`` (that driver's variant)."""
    parts = rel.split("/")[1:]
    device_type = parts[0] if len(parts) == 2 else ""
    if device_type and not _DEVICE_TYPE_RE.match(device_type):
        out.warn(rel, f"Skipped: '{device_type}' is not a driver name (lower-case letters, digits, '_').")
        return None
    name = _stem(parts[-1]).strip()
    if not name or len(name) > NAME_MAX:
        out.warn(rel, f"Skipped: the name must be 1 to {NAME_MAX} characters.")
        return None
    return Item("templates", rel, {"name": name, "device_type": device_type, "content": text, "description": ""})


def _playbook_item(rel: str, path: Path, text: str, out: Collected) -> Item | None:
    """``playbooks/<name>.yml``: an Ansible playbook (a YAML list of plays)."""
    from netcontrol.routes.playbooks import _sanitize_ansible_filename

    name = _stem(rel.split("/")[-1])
    try:
        filename = _sanitize_ansible_filename(name)
    except ValueError as exc:
        out.warn(rel, f"Skipped: {exc}")
        return None
    try:
        plays = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        out.warn(rel, f"Skipped: not valid YAML ({type(exc).__name__}).")
        return None
    if not isinstance(plays, list) or not all(isinstance(p, dict) for p in plays):
        out.warn(rel, "Skipped: an Ansible playbook must be a YAML list of plays.")
        return None
    description = ""
    if plays and isinstance(plays[0].get("name"), str):
        description = plays[0]["name"].strip()[:500]
    values = {
        "name": name,
        "filename": filename,
        "type": "ansible",
        "description": description,
        "tags": "[]",
        "content": text,
    }
    return Item("playbooks", rel, values)


def _context_item(rel: str, path: Path, text: str, out: Collected) -> Item | None:
    """``config_contexts/<name>.json|yml|yaml``: a JSON/YAML object whose
    optional ``_metadata`` key sets the name, weight, description, enabled
    and scope; everything else is the data."""
    try:
        data = json.loads(text) if rel.lower().endswith(".json") else yaml.safe_load(text)
    except (ValueError, yaml.YAMLError) as exc:
        out.warn(
            rel, f"Skipped: not valid {'JSON' if rel.lower().endswith('.json') else 'YAML'} ({type(exc).__name__})."
        )
        return None
    if not isinstance(data, dict):
        out.warn(rel, "Skipped: a config context must be an object (a mapping).")
        return None
    meta = data.pop(CONTEXT_METADATA_KEY, None) or {}
    if not isinstance(meta, dict):
        out.warn(rel, f"Skipped: '{CONTEXT_METADATA_KEY}' must be an object.")
        return None
    unknown = sorted(set(meta) - _CONTEXT_META_KEYS)
    if unknown:
        out.warn(rel, f"Skipped: unknown {CONTEXT_METADATA_KEY} key '{unknown[0]}'.")
        return None
    try:
        values = {
            "name": clean_name_value(meta.get("name", _stem(rel.split("/")[-1]))),
            "weight": clean_weight(meta.get("weight", 1000)),
            "data": clean_context_data(json.loads(json.dumps(data, default=str))),
            "description": clean_description(meta.get("description", "")),
            "enabled": 1 if meta.get("enabled", True) is not False else 0,
            "device_type": clean_device_type(meta.get("device_type", "")),
        }
        for key in ("role_id", "site_id", "group_id", "host_id"):
            value = meta.get(key)
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 1):
                raise CustomFieldError(f"{key} must be a positive whole number.")
            values[key] = value
        for key in ("group", "host"):
            value = meta.get(key)
            if value is not None:
                values[key] = clean_text(value, key.capitalize(), 255)
    except CustomFieldError as exc:
        out.warn(rel, f"Skipped: {exc}")
        return None
    return Item("config_contexts", rel, values)


_CONTEXT_META_KEYS = {
    "name",
    "weight",
    "description",
    "enabled",
    "device_type",
    "role_id",
    "site_id",
    "group_id",
    "host_id",
    "group",
    "host",
}

_READERS = {
    "templates": (TEMPLATE_EXTENSIONS, 1, _template_item),
    "playbooks": (PLAYBOOK_EXTENSIONS, 0, _playbook_item),
    "config_contexts": (CONTEXT_EXTENSIONS, 0, _context_item),
}


def _key(item: Item) -> tuple:
    if item.kind == "templates":
        return (item.values["name"], item.values["device_type"])
    if item.kind == "config_contexts":
        return (item.values["name"].lower(),)
    return (item.values["name"],)


def collect_items(workdir: str, provides: Iterable[str]) -> Collected:
    """The records of each provided content type in the checkout, with a
    warning for every file skipped (bad format, too large, a link, or a name
    already taken by an earlier file of the same type)."""
    root = Path(workdir)
    out = Collected()
    for kind in provides:
        extensions, depth, reader = _READERS[kind]
        items: list[Item] = []
        seen: dict[tuple, str] = {}
        for rel, path in _files(root, kind, extensions, out, depth=depth):
            text = _read_text(path, rel, out)
            if text is None:
                continue
            item = reader(rel, path, text, out)
            if item is None:
                continue
            key = _key(item)
            if key in seen:
                out.warn(rel, f"Skipped: same name as {seen[key]}.")
                continue
            seen[key] = rel
            items.append(item)
        out.items[kind] = items
    return out


def ignored_python_playbooks(workdir: str) -> list[str]:
    """Repository paths of ``playbooks/*.py`` files (Python playbooks are not
    imported from Git: they would run as server code)."""
    base = Path(workdir) / "playbooks"
    if not base.is_dir():
        return []
    return sorted(f"playbooks/{p.name}" for p in base.glob("*.py") if p.is_file() and not p.is_symlink())
