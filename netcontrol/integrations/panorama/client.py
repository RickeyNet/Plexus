"""Palo Alto Networks Panorama XML API client - paced, read-only.

Every request is ``GET https://<panorama>/api/`` with a ``type`` (``op`` for
an operational command, ``config`` with ``action=show`` for the running
configuration, ``version``) and the API key in the ``X-PAN-KEY`` header,
never in the URL, so the key cannot land in an access log. A key is either
given as is, or generated once per collection from a username and password
(``type=keygen``, sent as a POST form so the password is not in the URL
either). The key is never stored: an entry stores the key or the password.

An operational command for a managed firewall carries ``target=<serial>``:
Panorama relays it to the firewall and answers with the firewall's output.

Answers are XML (``<response status="success|error" code="...">``) and are
turned into plain JSON-safe values by :func:`xml_to_data`, which is what the
collector stores, so a saved capture can be re-normalised without calling
Panorama. The XML comes from the operator-configured management server;
``xml.etree.ElementTree`` parses it (defusedxml is not a dependency), and a
body that declares a DTD or entities is refused before parsing.

Scope
-----
Read-only: ``op`` ``show`` commands and ``config`` ``show``. Plexus never
commits, pushes or edits anything.

Failures
--------
The ``<msg>`` / ``<line>`` text of an error answer is kept as
:attr:`PanoramaApiError.detail`, which is what tells an operator why a
request was refused (a missing XML API permission, an unknown device).
"""

from __future__ import annotations

import asyncio
import time
import xml.etree.ElementTree as ElementTree
from typing import Any
from urllib.parse import urlsplit

import httpx

DEFAULT_TIMEOUT_SECONDS = 60.0
# Panorama's management plane serves the XML API alongside the web UI; a
# few requests a second keeps a collection from loading it.
DEFAULT_REQUESTS_PER_SECOND = 4.0
DEFAULT_MAX_RETRIES = 3

API_PATH = "/api/"
USER_AGENT = "Plexus-PanoramaTopology/1.0"

# PAN-OS error codes that mean "that node is not configured".
_ABSENT_CODES = ("7",)
_ABSENT_WORDS = ("no such node", "not present", "doesn't exist", "does not exist", "object not found")
_MAX_RETRY_AFTER_SECONDS = 60.0
_MAX_DETAIL_CHARS = 300
# Attributes PAN-OS adds to configuration elements that carry no meaning here.
_NOISE_ATTRIBUTES = ("admin", "dirtyId", "time")


class PanoramaApiError(RuntimeError):
    """A Panorama XML API request failed.

    ``status_code`` is the HTTP status for HTTP-level failures (``None`` for
    transport errors and for an error answer served with HTTP 200).
    ``code`` is the PAN-OS error code of an error answer, ``detail`` its
    message text.
    """

    def __init__(self, message: str, *, status_code: int | None = None, detail: str = "", code: str = "") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail
        self.code = code


def validate_base_url(url: str) -> str:
    """Normalise and validate the Panorama address.

    Accepts ``https://host[:port]`` (a bare host is taken as https) and
    returns just that: the URL decides where the credentials are sent, so no
    path, query or embedded user is allowed, and ``http`` is refused.
    Raises ``ValueError`` otherwise.
    """
    cleaned = (url or "").strip()
    if not cleaned:
        raise ValueError("Panorama address is required")
    if "://" not in cleaned:
        cleaned = f"https://{cleaned}"
    parts = urlsplit(cleaned)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("Panorama address must be an https URL")
    if parts.username or parts.password or parts.query or parts.fragment or parts.path.strip("/"):
        raise ValueError("Panorama address must be the host only")
    try:
        port = parts.port
    except ValueError:
        raise ValueError("Panorama address has an invalid port") from None
    host = parts.hostname
    if ":" in host:
        host = f"[{host}]"
    return f"https://{host}" + (f":{port}" if port else "")


# ── XML -> data ──────────────────────────────────────────────────────────────


def _member_text(element: ElementTree.Element) -> str:
    return (element.text or "").strip()


def xml_to_data(element: ElementTree.Element) -> Any:
    """An XML element as plain data.

    - ``<x><entry name="a">..</entry><entry name="b">..</entry></x>`` is a
      list of dicts, each with ``"@name"``
    - ``<x><member>a</member><member>b</member></x>`` is a list of strings
    - a text-only element is its text (``""`` when empty)
    - attributes are ``"@attr"`` keys (a leaf with attributes and text keeps
      the text as ``"#text"``)
    - a repeated child tag is a list; ``entry`` and ``member`` children of an
      element with other children too are always lists
    """
    children = list(element)
    attrs = {f"@{k}": v for k, v in element.attrib.items() if k not in _NOISE_ATTRIBUTES}
    text = (element.text or "").strip()
    if not children:
        if attrs:
            if text:
                attrs["#text"] = text
            return attrs
        return text
    tags = {child.tag for child in children}
    if tags == {"member"}:
        return [_member_text(child) for child in children]
    if tags == {"entry"}:
        return [xml_to_data(child) for child in children]
    counts: dict[str, int] = {}
    for child in children:
        counts[child.tag] = counts.get(child.tag, 0) + 1
    out: dict[str, Any] = dict(attrs)
    for child in children:
        value = _member_text(child) if child.tag == "member" else xml_to_data(child)
        if child.tag in ("entry", "member") or counts[child.tag] > 1:
            out.setdefault(child.tag, []).append(value)
        else:
            out[child.tag] = value
    return out


def result_value(result: ElementTree.Element | None) -> Any:
    """The data of a ``<result>`` element: ``None`` when it is empty, a list
    when it holds ``entry`` elements only, the single child's data when it
    holds one element with children (``{tag: text}`` for a single value),
    else the result itself as a dict."""
    if result is None:
        return None
    children = list(result)
    if not children:
        text = (result.text or "").strip()
        return text or None
    if all(child.tag == "entry" for child in children):
        return [xml_to_data(child) for child in children]
    if len(children) == 1:
        child = children[0]
        if len(child) or child.attrib:
            return xml_to_data(child)
        text = (child.text or "").strip()
        # An empty node is nothing configured; a single value keeps its name.
        return {child.tag: text} if text else None
    return xml_to_data(result)


def _parse(body: bytes) -> ElementTree.Element:
    # A DTD (and so any entity declaration) can only come before the root element.
    prolog = body.split(b"<response", 1)[0].lower()
    if b"<!doctype" in prolog or b"<!entity" in prolog:
        raise PanoramaApiError("Panorama answered with a document type declaration, which is refused")
    try:
        return ElementTree.fromstring(body)
    except ElementTree.ParseError:
        raise PanoramaApiError("Panorama answered with a body that is not XML") from None


def _message(root: ElementTree.Element) -> str:
    """The ``<msg>`` / ``<line>`` text of an answer."""
    lines: list[str] = []
    for tag in ("msg", "result/msg"):
        for msg in root.findall(tag):
            found = [(_member_text(line)) for line in msg.iter("line")]
            text = " ".join(t for t in found if t) or "".join(msg.itertext()).strip()
            if text:
                lines.append(text)
    return " ".join(" ".join(lines).split())[:_MAX_DETAIL_CHARS]


def _error_detail(resp: httpx.Response | None) -> str:
    if resp is None or not resp.content:
        return ""
    try:
        return _message(_parse(resp.content))
    except PanoramaApiError:
        return ""


def is_absent(exc: PanoramaApiError) -> bool:
    """Whether an error answer only says the node is not configured."""
    lowered = exc.detail.lower()
    return exc.code in _ABSENT_CODES or any(word in lowered for word in _ABSENT_WORDS)


class PanoramaClient:
    """Reusable Panorama XML API session.

    Give either ``api_key`` (used as is) or ``username`` and ``password``
    (an API key is generated at :meth:`login` and kept in memory only). Use
    as an async context manager, or call :meth:`close` when done.
    """

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str = "",
        username: str = "",
        password: str = "",
        verify_tls: bool = True,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        requests_per_second: float = DEFAULT_REQUESTS_PER_SECOND,
        max_retries: int = DEFAULT_MAX_RETRIES,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = validate_base_url(base_url)
        self._username = (username or "").strip()
        self._password = password or ""
        self._key = "" if self._username else (api_key or "").strip()
        self._verify_tls = verify_tls
        self._timeout = timeout
        self._max_retries = max(0, int(max_retries))
        self._transport = transport  # injectable for tests (httpx.MockTransport)
        self._client: httpx.AsyncClient | None = None

        self._min_interval = 1.0 / max(0.1, float(requests_per_second))
        self._lock = asyncio.Lock()
        self._next_slot = 0.0
        self._logged_in = False
        # What ``type=version`` answered.
        self.info: dict[str, str] = {}
        # Counters surfaced in the snapshot's collection report.
        self.stats = {"requests": 0, "retries": 0, "rate_limited": 0}

    async def __aenter__(self) -> PanoramaClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            # Redirects are never followed: the key must only ever reach the
            # validated Panorama host.
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self._timeout,
                verify=self._verify_tls,
                follow_redirects=False,
                transport=self._transport,
            )
        return self._client

    async def _wait_for_slot(self) -> None:
        now = time.monotonic()
        start = max(now, self._next_slot)
        self._next_slot = start + self._min_interval
        if start > now:
            await asyncio.sleep(start - now)

    # ── Login ──────────────────────────────────────────────────────────────

    async def _keygen(self) -> None:
        await self._wait_for_slot()
        self.stats["requests"] += 1
        try:
            resp = await self._ensure_client().post(
                API_PATH,
                data={"type": "keygen", "user": self._username, "password": self._password},
                headers={"User-Agent": USER_AGENT},
            )
        except httpx.HTTPError:
            raise PanoramaApiError("Could not reach Panorama") from None
        if resp.status_code >= 400:
            raise PanoramaApiError(
                f"Panorama rejected the credentials (HTTP {resp.status_code})"
                if resp.status_code in (401, 403)
                else f"Panorama keygen -> HTTP {resp.status_code}",
                status_code=resp.status_code,
                detail=_error_detail(resp),
            )
        root = _parse(resp.content)
        key = _member_text(root.find("result/key")) if root.find("result/key") is not None else ""
        if root.get("status") != "success" or not key:
            raise PanoramaApiError(
                "Panorama rejected the credentials", status_code=403, detail=_message(root), code=root.get("code") or ""
            )
        self._key = key

    async def login(self) -> None:
        """Generate the API key (with a username) and check it with a
        ``type=version`` call. Raises :class:`PanoramaApiError` when Panorama
        refuses or cannot be reached."""
        async with self._lock:
            await self._login()

    async def _login(self) -> None:
        if self._username:
            await self._keygen()
        elif not self._key:
            raise PanoramaApiError("No Panorama API key is set", status_code=403)
        self._logged_in = True
        root = await self._request({"type": "version"}, renew=False)
        found = result_value(root.find("result"))
        self.info = {k: str(v) for k, v in found.items() if isinstance(v, str)} if isinstance(found, dict) else {}

    # ── Requests ───────────────────────────────────────────────────────────

    async def _send(self, params: dict[str, str]) -> httpx.Response | None:
        self.stats["requests"] += 1
        try:
            return await self._ensure_client().get(
                API_PATH,
                params=params,
                headers={"X-PAN-KEY": self._key, "User-Agent": USER_AGENT},
            )
        except httpx.HTTPError:
            return None

    async def _request(self, params: dict[str, str], *, renew: bool = True) -> ElementTree.Element:
        """One call, answering the parsed ``<response>``; error answers raise."""
        attempt = 0
        what = params.get("cmd") or params.get("xpath") or params.get("type", "")
        while True:
            await self._wait_for_slot()
            resp = await self._send(params)
            if resp is not None and resp.status_code < 400:
                root = _parse(resp.content)
                if root.get("status") == "success":
                    return root
                exc = PanoramaApiError(
                    f"Panorama refused {params.get('type')} {what[:120]}",
                    detail=_message(root),
                    code=root.get("code") or "",
                )
                if renew and self._username and self._expired(exc):
                    renew = False
                    await self._keygen()
                    continue
                raise exc
            if resp is not None and resp.status_code in (401, 403):
                exc = PanoramaApiError(
                    f"Panorama rejected the API key (HTTP {resp.status_code})",
                    status_code=resp.status_code,
                    detail=_error_detail(resp),
                )
                if renew and self._username and self._expired(exc):
                    # The key expired: generate a new one, once.
                    renew = False
                    await self._keygen()
                    continue
                raise exc
            rate_limited = resp is not None and resp.status_code == 429
            retryable = resp is None or rate_limited or resp.status_code >= 500
            if not retryable or attempt >= self._max_retries:
                if resp is None:
                    raise PanoramaApiError(
                        f"Panorama {params.get('type')} {what[:120]} failed: could not reach Panorama"
                    )
                raise PanoramaApiError(
                    f"Panorama {params.get('type')} {what[:120]} -> HTTP {resp.status_code}",
                    status_code=resp.status_code,
                    detail=_error_detail(resp),
                )
            attempt += 1
            self.stats["retries"] += 1
            delay = min(2.0**attempt, 30.0)
            if rate_limited:
                self.stats["rate_limited"] += 1
                try:
                    delay = float(resp.headers.get("Retry-After", delay)) if resp is not None else delay
                except ValueError:
                    pass
                delay = min(max(delay, 2.0), _MAX_RETRY_AFTER_SECONDS)
            await asyncio.sleep(delay)

    @staticmethod
    def _expired(exc: PanoramaApiError) -> bool:
        lowered = exc.detail.lower()
        return "expired" in lowered or exc.code == "22"

    async def _call(self, params: dict[str, str]) -> ElementTree.Element:
        # One request at a time: Panorama's management plane is shared.
        async with self._lock:
            if not self._logged_in:
                await self._login()
            return await self._request(params)

    async def version(self) -> dict[str, str]:
        """What ``type=version`` answers (``sw-version``, ``model``, ``serial``...)."""
        if not self._logged_in:
            await self.login()
        return dict(self.info)

    async def op(self, cmd: str, target: str | None = None) -> Any:
        """An operational command (``<show>...</show>``), on Panorama itself
        or relayed to the managed firewall ``target`` (its serial)."""
        params = {"type": "op", "cmd": cmd}
        if target:
            params["target"] = target
        root = await self._call(params)
        return result_value(root.find("result"))

    async def config_show(self, xpath: str) -> Any:
        """The running configuration at ``xpath``; ``None`` when nothing is
        configured there."""
        try:
            root = await self._call({"type": "config", "action": "show", "xpath": xpath})
        except PanoramaApiError as exc:
            if exc.status_code is None and is_absent(exc):
                return None
            raise
        return result_value(root.find("result"))

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        self._logged_in = False
        if self._username:
            # A generated key lives for this session only.
            self._key = ""
