"""CVE enrichment of software advisories - NVD scores and the CISA KEV flag.

Two public feeds are read, by CVE id only (nothing about the tracked
devices is sent):

* the NVD CVE API 2.0 (``GET <base>?cveId=CVE-2024-3400``), one request per
  CVE, for the CVSS base score, severity and vector. The newest CVSS
  version NVD holds for the CVE is used (4.0, then 3.1, 3.0, 2.0), and
  within it the ``Primary`` metric (NVD's own) before a ``Secondary`` one
  (a CNA's). NVD allows 5 requests per rolling 30 seconds without an API
  key and 50 with one (sent in the ``apiKey`` header), so requests are
  spaced evenly inside that budget, and a refused or failed request is
  retried after a pause.
* the CISA Known Exploited Vulnerabilities catalogue, one JSON file, for
  the known-exploited flag with the date CISA added the CVE, the
  remediation due date and whether it is known to be used in ransomware
  campaigns.

The parsing and the severity rules are pure functions so they can be
tested from sample answers; :class:`NvdClient` and
:func:`fetch_kev_catalog` do the I/O. Redirects are not followed.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

import httpx

from netcontrol.integrations.http_common import RequestPacer, retry_delay
from netcontrol.integrations.software.psirt import _error_detail, _text
from netcontrol.integrations.software.versions import severity_at_least

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_RETRIES = 2
# NVD's published limits: requests per rolling 30 second window.
NVD_WINDOW_SECONDS = 30.0
NVD_REQUESTS_PER_WINDOW = 5
NVD_REQUESTS_PER_WINDOW_WITH_KEY = 50
# Lookups per run: about ten minutes at the pace of each limit. The rest
# are looked up by the next run.
MAX_LOOKUPS_PER_RUN = 100
MAX_LOOKUPS_PER_RUN_WITH_KEY = 1000
# A scored CVE is asked again after a week (NVD revises scores); one NVD has
# not scored yet, or does not know, after a day.
SCORED_REFRESH_DAYS = 7
UNSCORED_REFRESH_DAYS = 1

# Lookup states of a cached CVE.
STATE_PENDING = "pending"  # never answered (or only failed so far)
STATE_SCORED = "scored"
STATE_UNSCORED = "unscored"  # NVD knows the CVE but has no CVSS metric yet
STATE_NOT_FOUND = "not_found"

# Where an advisory's severity comes from (``software_advisories.severity_source``).
SEVERITY_DEFAULT = "default"  # the source gave none: enrichment may set it
SEVERITY_ENRICHED = "enriched"  # set from the CVSS score / KEV flag
SEVERITY_VENDOR = "vendor"  # the vendor's own rating (Cisco PSIRT): kept
SEVERITY_ADMIN = "admin"  # set by an administrator: kept
SEVERITY_SOURCES = (SEVERITY_DEFAULT, SEVERITY_ENRICHED, SEVERITY_VENDOR, SEVERITY_ADMIN)
CVSS_FROM_NVD = "nvd"

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,19}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# Newest CVSS version first.
_METRIC_KEYS = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)
_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
_MAX_ERROR_CHARS = 300


class CveFeedError(RuntimeError):
    """A request NVD or the KEV host refused or could not answer.

    ``status_code`` is the HTTP status (0 when no answer arrived) and
    ``rate_limited`` tells a refusal that ends the run's lookups (HTTP 403
    or 429: rate limit or a rejected API key) from a failure of one CVE.
    """

    def __init__(self, message: str, *, status_code: int = 0, rate_limited: bool = False) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.rate_limited = rate_limited


# ── Parsing ──────────────────────────────────────────────────────────────────


def normalize_cve_id(value: Any) -> str:
    """``value`` as an upper-case CVE id, or ``""`` when it is not one."""
    text = _text(value).upper()
    return text if _CVE_ID_RE.match(text) else ""


def cve_ids(values: Iterable[Any] | None) -> list[str]:
    """The valid CVE ids of ``values``, upper-cased, first occurrence kept."""
    found: list[str] = []
    for value in values or []:
        cve = normalize_cve_id(value)
        if cve and cve not in found:
            found.append(cve)
    return found


def _score(value: Any) -> float | None:
    try:
        score = float(value)
    except TypeError, ValueError:
        return None
    return score if 0.0 <= score <= 10.0 else None


def _best_metric(metrics: Any) -> tuple[str, dict, dict] | None:
    """``(cvss_version, metric, cvssData)`` of the metric to use: the newest
    version present, the ``Primary`` metric before a ``Secondary`` one."""
    if not isinstance(metrics, dict):
        return None
    for key, version in _METRIC_KEYS:
        items = [m for m in metrics.get(key) or [] if isinstance(m, dict) and isinstance(m.get("cvssData"), dict)]
        items = [m for m in items if _score(m["cvssData"].get("baseScore")) is not None]
        if not items:
            continue
        primary = next((m for m in items if _text(m.get("type")) == "Primary"), None)
        metric = primary or items[0]
        return version, metric, metric["cvssData"]
    return None


def parse_nvd_cve(body: Any, cve_id: str) -> dict[str, Any]:
    """One NVD CVE API 2.0 answer for ``cve_id`` as a cache entry:
    ``lookup_state`` (``scored``, ``unscored`` or ``not_found``),
    ``nvd_status`` (NVD's ``vulnStatus``), ``cvss``, ``cvss_severity``
    (lower case), ``cvss_vector`` and ``cvss_version``."""
    cve_id = normalize_cve_id(cve_id)
    entry: dict[str, Any] = {
        "cve_id": cve_id,
        "lookup_state": STATE_NOT_FOUND,
        "nvd_status": "",
        "cvss": None,
        "cvss_severity": "",
        "cvss_vector": "",
        "cvss_version": "",
    }
    vulnerabilities = body.get("vulnerabilities") if isinstance(body, dict) else None
    cve: dict | None = None
    for item in vulnerabilities or []:
        candidate = item.get("cve") if isinstance(item, dict) else None
        if isinstance(candidate, dict) and normalize_cve_id(candidate.get("id")) == cve_id:
            cve = candidate
            break
    if cve is None:
        return entry
    entry["nvd_status"] = _text(cve.get("vulnStatus"))[:60]
    best = _best_metric(cve.get("metrics"))
    if best is None:
        entry["lookup_state"] = STATE_UNSCORED
        return entry
    version, metric, data = best
    # CVSS 3.x and 4.0 carry the severity in cvssData, CVSS 2.0 on the metric.
    severity = _text(data.get("baseSeverity") or metric.get("baseSeverity")).lower()
    entry.update(
        lookup_state=STATE_SCORED,
        cvss=_score(data.get("baseScore")),
        cvss_severity=severity[:20],
        cvss_vector=_text(data.get("vectorString"))[:300],
        cvss_version=_text(data.get("version")) or version,
    )
    return entry


def parse_kev_catalog(body: Any) -> dict[str, dict[str, str]]:
    """The CISA KEV catalogue as ``{cve_id: {"date_added", "due_date",
    "ransomware"}}``. Raises ``ValueError`` for a body that is not the
    catalogue (no ``vulnerabilities`` list)."""
    if not isinstance(body, dict) or not isinstance(body.get("vulnerabilities"), list):
        raise ValueError("not a CISA KEV catalogue")
    catalog: dict[str, dict[str, str]] = {}
    for item in body["vulnerabilities"]:
        if not isinstance(item, dict):
            continue
        cve = normalize_cve_id(item.get("cveID"))
        if not cve:
            continue
        added, due = _text(item.get("dateAdded")), _text(item.get("dueDate"))
        catalog[cve] = {
            "date_added": added if _DATE_RE.match(added) else "",
            "due_date": due if _DATE_RE.match(due) else "",
            "ransomware": _text(item.get("knownRansomwareCampaignUse"))[:20],
        }
    return catalog


# ── Rules ────────────────────────────────────────────────────────────────────


def severity_for_score(score: float | None) -> str | None:
    """The severity band of a CVSS base score: critical from 9.0, high from
    7.0, medium from 4.0, low below; ``None`` without a score."""
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _parse_time(value: Any) -> datetime | None:
    try:
        return datetime.strptime(_text(value), _TIME_FORMAT)
    except ValueError:
        return None


def lookup_due(entry: dict | None, now: datetime) -> bool:
    """Whether NVD should be asked about a cached CVE again: never answered,
    a score older than :data:`SCORED_REFRESH_DAYS`, or no score (or not
    found) for longer than :data:`UNSCORED_REFRESH_DAYS`. ``now`` is naive
    UTC, as the stored times."""
    if not entry:
        return True
    checked = _parse_time(entry.get("nvd_checked_at"))
    state = entry.get("lookup_state")
    if checked is None or state not in (STATE_SCORED, STATE_UNSCORED, STATE_NOT_FOUND):
        return True
    days = SCORED_REFRESH_DAYS if state == STATE_SCORED else UNSCORED_REFRESH_DAYS
    return now - checked >= timedelta(days=days)


def lookup_order(cves: Iterable[str], cache: dict[str, dict], now: datetime) -> list[str]:
    """The CVEs of ``cves`` that are due, never-answered first, then the
    longest unchecked."""
    due = [cve for cve in cves if lookup_due(cache.get(cve), now)]
    # "" (never answered) sorts before every time.
    return sorted(due, key=lambda cve: str((cache.get(cve) or {}).get("nvd_checked_at") or ""))


def advisory_enrichment(advisory: dict, cache: dict[str, dict]) -> dict[str, Any]:
    """The enrichment fields of one advisory from the cached entries of its
    CVEs.

    ``cvss`` becomes the highest NVD base score of its CVEs when the
    advisory has no score of its own (``cvss_source`` ``nvd`` marks one
    filled this way). The severity is derived from the score (and raised to
    at least ``high`` when a CVE is known exploited) only while its
    ``severity_source`` is ``default`` or ``enriched``: a vendor's or an
    administrator's severity is kept. The KEV fields are the earliest date
    added and due date among the advisory's known-exploited CVEs, and
    ``Known`` when any is used in ransomware campaigns.
    """
    rows = [cache[cve] for cve in cve_ids(advisory.get("cves")) if cve in cache]
    scores = [score for score in (_score(row.get("cvss")) for row in rows) if score is not None]
    best = max(scores) if scores else None
    cvss = advisory.get("cvss")
    cvss_source = str(advisory.get("cvss_source") or "")
    if (cvss is None or cvss_source == CVSS_FROM_NVD) and best is not None:
        cvss, cvss_source = best, CVSS_FROM_NVD
    kev_rows = [row for row in rows if row.get("known_exploited")]
    severity = str(advisory.get("severity") or "medium")
    severity_source = str(advisory.get("severity_source") or SEVERITY_DEFAULT)
    if severity_source in (SEVERITY_DEFAULT, SEVERITY_ENRICHED):
        derived = severity_for_score(_score(cvss))
        if kev_rows and (derived is None or not severity_at_least(derived, "high")):
            derived = "high"
        if derived:
            severity, severity_source = derived, SEVERITY_ENRICHED
    added = sorted(str(row.get("kev_date_added") or "") for row in kev_rows if row.get("kev_date_added"))
    due = sorted(str(row.get("kev_due_date") or "") for row in kev_rows if row.get("kev_due_date"))
    ransomware = ""
    if kev_rows:
        known = any(str(row.get("kev_ransomware") or "").lower() == "known" for row in kev_rows)
        ransomware = "Known" if known else "Unknown"
    return {
        "cvss": cvss,
        "cvss_source": cvss_source,
        "severity": severity,
        "severity_source": severity_source,
        "known_exploited": bool(kev_rows),
        "kev_date_added": added[0] if added else "",
        "kev_due_date": due[0] if due else "",
        "kev_ransomware": ransomware,
    }


def enrichment_changed(advisory: dict, fields: dict[str, Any]) -> bool:
    """Whether ``fields`` differ from what ``advisory`` holds."""
    for key, value in fields.items():
        current = advisory.get(key)
        if key == "known_exploited":
            current = bool(current)
        elif key in ("cvss_source", "severity_source", "kev_date_added", "kev_due_date", "kev_ransomware"):
            current = str(current or "")
        if current != value:
            return True
    return False


def validate_feed_url(url: str, label: str) -> str:
    """A configured feed address (an NVD or KEV mirror), stripped; ``""``
    keeps the default. Raises ``ValueError`` naming ``label`` unless it is
    an ``https`` URL with a host and no user, query or fragment."""
    cleaned = (url or "").strip()
    if not cleaned:
        return ""
    try:
        parts = urlsplit(cleaned)
        _ = parts.port  # raises ValueError for an invalid port
    except ValueError:
        raise ValueError(f"{label} is not a valid URL") from None
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError(f"{label} must be an https URL")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError(f"{label} must not contain a user, a query or a fragment")
    return cleaned


def max_lookups_per_run(has_api_key: bool) -> int:
    return MAX_LOOKUPS_PER_RUN_WITH_KEY if has_api_key else MAX_LOOKUPS_PER_RUN


# ── I/O ──────────────────────────────────────────────────────────────────────


def _client(timeout: float, transport: httpx.AsyncBaseTransport | None) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        transport=transport,
        headers={"Accept": "application/json", "User-Agent": "Plexus-SoftwareTracker/1.0"},
    )


def _detail(resp: httpx.Response | None) -> str:
    # NVD explains a refusal in a ``message`` header as well as in the body.
    if resp is not None and resp.headers.get("message"):
        return resp.headers["message"][:_MAX_ERROR_CHARS]
    return _error_detail(resp)


class NvdClient:
    """NVD CVE API 2.0 session. Use as an async context manager.

    ``requests_per_second`` defaults to NVD's limit for the key in use;
    ``transport`` is injectable for tests (``httpx.MockTransport``).
    """

    def __init__(
        self,
        *,
        base_url: str = NVD_API_URL,
        api_key: str = "",
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        requests_per_second: float | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._base_url = base_url or NVD_API_URL
        self._api_key = api_key
        self._timeout = timeout
        self._max_retries = max(0, int(max_retries))
        self._transport = transport
        self._client: httpx.AsyncClient | None = None
        if requests_per_second is None:
            per_window = NVD_REQUESTS_PER_WINDOW_WITH_KEY if api_key else NVD_REQUESTS_PER_WINDOW
            requests_per_second = per_window / NVD_WINDOW_SECONDS
        self._pacer = RequestPacer(requests_per_second)
        self.stats = {"requests": 0, "retries": 0, "rate_limited": 0}

    async def __aenter__(self) -> NvdClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _get(self, cve_id: str) -> httpx.Response | None:
        if self._client is None:
            self._client = _client(self._timeout, self._transport)
        headers = {"apiKey": self._api_key} if self._api_key else {}
        self.stats["requests"] += 1
        try:
            return await self._client.get(self._base_url, params={"cveId": cve_id}, headers=headers)
        except httpx.HTTPError:
            return None

    async def lookup(self, cve_id: str) -> dict[str, Any]:
        """The cache entry of ``cve_id`` (see :func:`parse_nvd_cve`). Raises
        :class:`CveFeedError` when NVD refuses or fails after the retries."""
        cve = normalize_cve_id(cve_id)
        if not cve:
            raise CveFeedError(f"{cve_id!r} is not a CVE id")
        attempt = 0
        while True:
            await self._pacer.wait()
            resp = await self._get(cve)
            if resp is not None and resp.status_code == 200:
                try:
                    return parse_nvd_cve(resp.json(), cve)
                except ValueError as exc:
                    raise CveFeedError("NVD answered with something other than JSON", status_code=200) from exc
            if resp is not None and resp.status_code == 404:
                return parse_nvd_cve({}, cve)
            status = resp.status_code if resp is not None else 0
            refused = status in (403, 429)
            retryable = resp is None or refused or status >= 500
            if not retryable or attempt >= self._max_retries:
                detail = _detail(resp)
                if refused:
                    message = f"NVD refused the request (HTTP {status}): rate limit reached or API key rejected"
                elif status:
                    message = f"NVD request failed (HTTP {status})"
                else:
                    message = "NVD is unreachable or did not answer in time"
                raise CveFeedError(
                    f"{message}: {detail}" if detail else message, status_code=status, rate_limited=refused
                )
            attempt += 1
            self.stats["retries"] += 1
            if refused:
                self.stats["rate_limited"] += 1
            retry_after = resp.headers.get("Retry-After") if resp is not None else None
            await _sleep(retry_delay(attempt, rate_limited=refused, retry_after=retry_after))


async def fetch_kev_catalog(
    url: str = KEV_URL,
    *,
    request_timeout: float = DEFAULT_TIMEOUT_SECONDS,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, dict[str, str]]:
    """Download and parse the CISA KEV catalogue (one request). Raises
    :class:`CveFeedError` when it cannot be read."""
    async with _client(request_timeout, transport) as client:
        try:
            resp = await client.get(url or KEV_URL)
        except httpx.HTTPError as exc:
            raise CveFeedError(f"CISA KEV catalogue is unreachable: {type(exc).__name__}") from exc
    if resp.status_code != 200:
        raise CveFeedError(
            f"CISA KEV catalogue download failed (HTTP {resp.status_code})", status_code=resp.status_code
        )
    try:
        return parse_kev_catalog(resp.json())
    except ValueError as exc:
        raise CveFeedError("CISA KEV answer is not the catalogue JSON", status_code=200) from exc


async def _sleep(seconds: float) -> None:
    # Module-level so tests can skip the pause.
    await asyncio.sleep(seconds)
