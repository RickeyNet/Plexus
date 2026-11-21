"""software_cve.py -- NVD and CISA KEV enrichment of the software advisories.

Off by default: a run sends CVE ids (and nothing else) to the NVD API and
downloads the CISA KEV catalogue, which an air-gapped deployment cannot
reach. When it is turned on (Software settings), a run:

1. collects the CVE ids of every advisory, whatever its source;
2. downloads the KEV catalogue once and records for each CVE whether it is
   known exploited;
3. asks NVD about the CVEs that are due (never answered, a score older
   than a week, no score yet for longer than a day), at most
   :func:`~netcontrol.integrations.software.cve_enrichment.max_lookups_per_run`
   per run, paced to NVD's rate limit; the rest wait for the next run;
4. derives each advisory's CVSS score, severity and KEV fields from the
   cached CVEs (``cve_enrichment.advisory_enrichment``) and stores what
   changed;
5. re-evaluates the alerts, so open alerts carry the new severity; an
   advisory that was enriched before and has now become known exploited
   has its open alerts handed to the notification channels again.

A run happens after the scheduled software refresh when it is due, or on
**Run now** (a background job). A failure is logged and recorded in the
settings view; it never fails the refresh, and what is stored is kept.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

import routes.database as db

from netcontrol.integrations.http_common import guard_api_host
from netcontrol.integrations.software.cve_enrichment import (
    KEV_URL,
    NVD_API_URL,
    CveFeedError,
    NvdClient,
    advisory_enrichment,
    cve_ids,
    enrichment_changed,
    fetch_kev_catalog,
    lookup_order,
    max_lookups_per_run,
    validate_feed_url,
)
from netcontrol.routes import background_jobs
from netcontrol.routes.shared import _audit, supervise_task
from netcontrol.secret_fields import refuse_secret_reuse, url_origin
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.software")

JOB_KIND = "software-cve-enrichment"
# A full run (KEV download, due lookups) at most this often; a run that left
# CVEs for later is followed by the next scheduled refresh.
RUN_INTERVAL_SECONDS = 12 * 60 * 60
_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
_MAX_ERRORS = 20
# Consecutive failed lookups after which a run stops asking NVD.
_MAX_CONSECUTIVE_FAILURES = 3

SETTING_DEFAULTS = {"cve_enrichment_enabled": "false", "nvd_base_url": "", "kev_url": ""}

_running = False
# Injectable for tests (httpx.MockTransport), and the NVD pace.
_TRANSPORT: Any = None
_REQUESTS_PER_SECOND: float | None = None

Evaluate = Callable[..., Awaitable[dict[str, Any]]]


def _enabled(raw: dict[str, str]) -> bool:
    return str(raw.get("cve_enrichment_enabled") or "").strip().lower() == "true"


def _last_counts(raw: dict[str, str]) -> dict[str, Any]:
    try:
        counts = json.loads(raw.get("cve_last_run_counts") or "{}")
    except ValueError:
        return {}
    return counts if isinstance(counts, dict) else {}


def is_running() -> bool:
    return _running


def public_settings(raw: dict[str, str]) -> dict[str, Any]:
    """The enrichment part of the software settings view (no API key)."""
    return {
        "cve_enrichment_enabled": _enabled(raw),
        "has_nvd_api_key": bool(raw.get("nvd_api_key_enc")),
        "nvd_base_url": raw.get("nvd_base_url") or "",
        "kev_url": raw.get("kev_url") or "",
        "nvd_default_url": NVD_API_URL,
        "kev_default_url": KEV_URL,
        "cve_last_run_at": raw.get("cve_last_run_at") or "",
        "cve_last_run_status": raw.get("cve_last_run_status") or "",
        "cve_last_run_message": raw.get("cve_last_run_message") or "",
        "cve_last_run_counts": _last_counts(raw),
        "cve_running": _running,
    }


async def settings_update(
    raw: dict[str, str],
    *,
    enabled: bool | None,
    api_key: str | None,
    nvd_base_url: str | None,
    kev_url: str | None,
) -> dict[str, str]:
    """The ``software_settings`` values of an enrichment settings change.

    ``api_key`` is write-only (``None`` keeps the stored key, ``""`` clears
    it). A mirror address must be an https URL the outbound address guard
    accepts, and a stored API key is not sent to a new NVD host unless the
    same change enters it again. Raises ``ValueError`` with the reason.
    """
    values: dict[str, str] = {}
    if enabled is not None:
        values["cve_enrichment_enabled"] = "true" if enabled else "false"
    for key, url, label in (("nvd_base_url", nvd_base_url, "NVD API URL"), ("kev_url", kev_url, "CISA KEV URL")):
        if url is None:
            continue
        cleaned = validate_feed_url(url, label)
        if cleaned:
            await guard_api_host(cleaned, label, ValueError)
        values[key] = cleaned
    if "nvd_base_url" in values:
        stored = ["NVD API key"] if raw.get("nvd_api_key_enc") and api_key != "" else []
        refuse_secret_reuse(
            {"nvd_url": url_origin(raw.get("nvd_base_url") or NVD_API_URL)},
            {"nvd_url": url_origin(values["nvd_base_url"] or NVD_API_URL)},
            ("nvd_url",),
            stored=stored,
            resent=["NVD API key"] if api_key else [],
        )
    if api_key is not None:
        if api_key.strip():
            from routes.crypto import encrypt

            values["nvd_api_key_enc"] = encrypt(api_key.strip())
        else:
            values["nvd_api_key_enc"] = ""
    return values


def scheduled_run_due(raw: dict[str, str], now: datetime | None = None) -> bool:
    """Whether the scheduler should run enrichment now: turned on, not
    running, and never run, or the last run left CVEs for later, or it was
    :data:`RUN_INTERVAL_SECONDS` ago."""
    if not _enabled(raw) or _running:
        return False
    last = raw.get("cve_last_run_at") or ""
    try:
        last_at = datetime.strptime(last, _TIME_FORMAT).replace(tzinfo=UTC) if last else None
    except ValueError:
        last_at = None
    if last_at is None or int(_last_counts(raw).get("remaining") or 0) > 0:
        return True
    return ((now or datetime.now(UTC)) - last_at).total_seconds() >= RUN_INTERVAL_SECONDS


async def _feed_urls(raw: dict[str, str]) -> tuple[str, str]:
    """The NVD and KEV addresses of this run; a mirror is checked by the
    outbound address guard again (its address may resolve elsewhere now)."""
    urls = []
    for key, default, label in (("nvd_base_url", NVD_API_URL, "NVD API URL"), ("kev_url", KEV_URL, "CISA KEV URL")):
        url = (raw.get(key) or "").strip()
        if url:
            await guard_api_host(url, label, CveFeedError)
        urls.append(url or default)
    return urls[0], urls[1]


def _api_key(raw: dict[str, str]) -> str:
    encrypted = raw.get("nvd_api_key_enc") or ""
    if not encrypted:
        return ""
    from routes.crypto import decrypt

    try:
        return decrypt(encrypted)
    except RuntimeError as exc:
        raise CveFeedError("The stored NVD API key cannot be decrypted; enter it again") from exc


def _progress(job_id: str | None, **fields: Any) -> None:
    if job_id:
        background_jobs.update_progress(job_id, **fields)


async def _enrich(job_id: str | None, raw: dict[str, str], evaluate: Evaluate) -> dict[str, Any]:
    now = datetime.now(UTC)
    checked_at = now.strftime(_TIME_FORMAT)
    errors: list[str] = []
    nvd_url, kev_url = await _feed_urls(raw)
    api_key = _api_key(raw)
    advisories = await db.list_software_advisories()
    wanted = sorted({cve for advisory in advisories for cve in cve_ids(advisory.get("cves"))})

    _progress(job_id, phase="kev", done=0, total=len(wanted))
    known_exploited = None
    kev_ok = False
    try:
        catalog = await fetch_kev_catalog(kev_url, transport=_TRANSPORT)
        known_exploited = await db.store_cve_kev(wanted, catalog, checked_at)
        kev_ok = True
    except CveFeedError as exc:
        errors.append(f"CISA KEV: {exc}")
        LOGGER.warning("software: CISA KEV download failed: %s", exc)

    cache = await db.list_cve_enrichment()
    due = lookup_order(wanted, cache, now.replace(tzinfo=None))
    batch = due[: max_lookups_per_run(bool(api_key))]
    looked_up = failed = consecutive = 0
    stopped = 0
    _progress(job_id, phase="nvd", done=0, total=len(batch))
    async with NvdClient(
        base_url=nvd_url, api_key=api_key, requests_per_second=_REQUESTS_PER_SECOND, transport=_TRANSPORT
    ) as client:
        for index, cve in enumerate(batch):
            _progress(job_id, done=index, current=cve)
            try:
                entry = await client.lookup(cve)
            except CveFeedError as exc:
                failed += 1
                consecutive += 1
                await db.store_cve_lookup_error(cve, str(exc))
                if exc.rate_limited or consecutive >= _MAX_CONSECUTIVE_FAILURES:
                    errors.append(f"NVD: {exc}; stopped after {index + 1} of {len(batch)} lookup(s)")
                    stopped = len(batch) - index - 1
                    LOGGER.warning("software: NVD lookups stopped: %s", exc)
                    break
                errors.append(f"NVD {cve}: {exc}")
                continue
            consecutive = 0
            await db.store_cve_lookup(entry, datetime.now(UTC).strftime(_TIME_FORMAT))
            looked_up += 1
    remaining = len(due) - len(batch) + stopped + failed

    _progress(job_id, phase="advisories", done=len(batch))
    cache = await db.list_cve_enrichment()
    # Re-notify only when both this run and the last one read the KEV
    # catalogue, so neither the first run nor a recovered download does.
    compare_kev = kev_ok and bool(_last_counts(raw).get("kev_downloaded"))
    updated, became_exploited = await apply_cached_enrichment(cache=cache, compare_kev=compare_kev)

    _progress(job_id, phase="matching")
    alerts = await evaluate(notify=True, renotify_advisories=became_exploited)
    counts = {
        "cves": len(wanted),
        "looked_up": looked_up,
        "failed": failed,
        "remaining": remaining,
        "known_exploited": known_exploited
        if known_exploited is not None
        else sum(1 for cve in wanted if (cache.get(cve) or {}).get("known_exploited")),
        "kev_downloaded": kev_ok,
        "advisories_updated": updated,
        "became_known_exploited": len(became_exploited),
    }
    message = (
        f"{len(wanted)} CVE(s): {looked_up} looked up at NVD, {counts['known_exploited']} known exploited, "
        f"{updated} advisory(ies) updated"
    )
    if remaining:
        message += f", {remaining} left for the next run"
    if errors:
        message += f"; {len(errors)} problem(s): {errors[0]}"
    status = "partial" if errors else "completed"
    if not kev_ok and batch and not looked_up:
        status = "failed"
    return {"status": status, "message": message, "counts": counts, "errors": errors[:_MAX_ERRORS], "alerts": alerts}


async def apply_cached_enrichment(
    only: set[str] | None = None, *, cache: dict[str, dict] | None = None, compare_kev: bool = False
) -> tuple[int, set[str]]:
    """Derive and store the enrichment of every advisory with CVE ids (or of
    the advisories ``only`` names) from the cached CVE entries; no request
    is sent. Returns how many advisories changed and, with ``compare_kev``,
    those that were enriched before and have now become known exploited."""
    if cache is None:
        cache = await db.list_cve_enrichment()
    updated = 0
    became_exploited: set[str] = set()
    # Read now: an advisory may have been edited while NVD was asked.
    for advisory in await db.list_software_advisories():
        if (only is not None and advisory["advisory_id"] not in only) or not cve_ids(advisory.get("cves")):
            continue
        fields = advisory_enrichment(advisory, cache)
        changed = enrichment_changed(advisory, fields)
        if not changed and advisory.get("enriched_at"):
            continue
        await db.apply_advisory_enrichment(advisory["advisory_id"], fields)
        updated += int(changed)
        # Only an advisory enriched before: a new one's alerts were notified as new.
        newly = fields["known_exploited"] and not advisory.get("known_exploited")
        if newly and compare_kev and advisory.get("enriched_at"):
            became_exploited.add(advisory["advisory_id"])
    return updated, became_exploited


async def run_cve_enrichment(job_id: str | None, user: str, evaluate: Evaluate) -> dict[str, Any]:
    """One enrichment run (see the module docstring). Never raises: the
    outcome is recorded in the settings and returned."""
    global _running
    _running = True
    started = datetime.now(UTC).strftime(_TIME_FORMAT)
    try:
        raw = {**SETTING_DEFAULTS, **await db.get_software_settings()}
        result = await _enrich(job_id, raw, evaluate)
    except CveFeedError as exc:
        result = {"status": "failed", "message": str(exc), "counts": {}, "errors": [str(exc)]}
    except Exception as exc:  # noqa: BLE001 - the run must reach a terminal state
        LOGGER.exception("software: CVE enrichment crashed: %s", type(exc).__name__)
        message = "CVE enrichment failed; see the server log for details"
        result = {"status": "failed", "message": message, "counts": {}, "errors": [message]}
    finally:
        _running = False
    if job_id:
        if result["status"] == "failed":
            background_jobs.finish_job(job_id, "failed", error=result["message"], result=result)
        else:
            background_jobs.finish_job(job_id, result["status"], result=result)
    try:
        await db.set_software_settings(
            {
                "cve_last_run_at": started,
                "cve_last_run_status": result["status"],
                "cve_last_run_message": result["message"][:1000],
                "cve_last_run_counts": json.dumps(result.get("counts") or {}),
            }
        )
        await _audit("software", "cve_enrichment", user=user, detail=f"status={result['status']} {result['message']}")
    except Exception as exc:  # noqa: BLE001 - recording the outcome must not raise
        LOGGER.warning("software: could not record the CVE enrichment run: %s", type(exc).__name__)
    return result


def start_job(user: str, evaluate: Evaluate) -> dict:
    """Start a run as a background job. Raises ``RuntimeError`` when one is
    already running."""
    global _running
    if _running:
        raise RuntimeError("A CVE enrichment run is already running")
    _running = True
    job = background_jobs.create_job(JOB_KIND, {"phase": "starting"})
    supervise_task(asyncio.create_task(run_cve_enrichment(job["job_id"], user, evaluate)), "software-cve-enrichment")
    return job


def get_job(job_id: str) -> dict | None:
    return background_jobs.get_job(job_id, kind=JOB_KIND)
