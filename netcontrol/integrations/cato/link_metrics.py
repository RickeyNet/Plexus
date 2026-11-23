"""Cato Socket WAN link RTT, jitter and loss from ``accountMetrics``.

``collect_link_metrics`` reads the five-minute history of every site's
links over the time since the newest stored sample
(``netcontrol.integrations.link_metrics``) with Cato's ``accountMetrics``
query; ``link_metric_samples`` turns the answer into one sample per link
and bucket, which ``normalize`` puts on the Socket's WAN link edge as
``metric_samples``.

What Cato documents (Cato API reference, "AccountMetrics",
"AccountMetrics > Timeseries", "AccountMetrics > Sites > Interfaces",
"Working with accountMetrics Granularity", "Understanding Cato API Rate
Limiting"; the field and argument names as in the schema payload of Cato's
CLI, ``catonetworks/cato-cli``, ``queryPayloads/query.accountMetrics.txt``):

  - ``accountMetrics(accountID, timeFrame, groupDevices, groupInterfaces)``:
    ``timeFrame`` ``last.<ISO-8601 duration>`` (``last.PT65M``);
    ``groupDevices: true`` aggregates the Sockets of a site (an HA pair) and
    is mandatory for a query over several sites; ``groupInterfaces: false``
    keeps one entry per link.
  - ``sites(siteIDs) { id interfaces { name interfaceInfo { id name }
    timeseries(buckets, labels) { label units data } } }``: ``name`` is
    the link's name in the Cato Management Application; ``data`` is a list
    of ``[timestamp, value]``, the timestamp in milliseconds since the epoch
    (the start of the bucket); ``units`` one of ms, percent...
  - bucket size (granularity) = timeFrame / buckets, at least 5 seconds.
  - labels read: ``rtt`` (round trip time from the site to the Cato Cloud,
    ms), ``jitterUpstream`` / ``jitterDownstream`` (the difference in delay
    between packets, ms; Cato's reference page spells the first
    ``jitterUptstream``, the schema ``jitterUpstream``), ``lostUpstreamPcnt``
    / ``lostDownstreamPcnt`` (percent of packets lost, per direction).
  - limits: at most 100,000 returned items per query ((sites + users) x
    labels x buckets); 15 ``accountMetrics`` queries a minute per account;
    the data is "typically available within a 5 minutes time frame".

What a sample holds (per link and five-minute bucket):

  - ``latency_ms``: ``rtt``. A bucket with no RTT (0 or none: no traffic
    measured) gives no sample at all, its loss being meaningless then.
  - ``jitter_ms``: the larger of the upstream and downstream jitter Cato
    reports (the worse direction; Cato's own values, not derived).
  - ``loss_pct``: the larger of the upstream and downstream loss percent.

The newest ``_SETTLE_SECONDS`` of the answer are dropped (not settled yet);
buckets of consecutive reads need not line up, so a bucket that overlaps
one already stored is left out (``link_metrics.new_samples``).

Which link a measurement belongs to: the site's ``id``, then the
interface's ``interfaceInfo.id`` (matched to the id ``accountSnapshot``
gives the Socket's interface) or else its name. With
``groupDevices`` the two Sockets of an HA site are one, so the measurement
is filed under the primary Socket's link. An IPsec site (no Socket) is not
matched. Not checked against a live account: the interface ids
``accountMetrics`` returns are taken to be the ids ``accountSnapshot``
returns.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from netcontrol.integrations.cato.client import CatoApiError, CatoClient, error_entry
from netcontrol.integrations.link_metrics import WINDOW_SECONDS, clamp_lookback, make_sample, number, worst
from netcontrol.integrations.traffic import parse_time

LABELS = ("rtt", "jitterUpstream", "jitterDownstream", "lostUpstreamPcnt", "lostDownstreamPcnt")
# Sites per query: 50 sites x 5 labels x at most 75 buckets x a few links
# stays well under Cato's 100,000 items per query.
SITES_PER_QUERY = 50
# Cato has the data within about five minutes: newer buckets are dropped.
_SETTLE_SECONDS = 300
PATH = "accountMetrics (link RTT, jitter, loss)"

_QUERY = """
query plexusLinkMetrics($accountID: ID!, $timeFrame: TimeFrame!, $siteIDs: [ID!],
                        $buckets: Int, $labels: [TimeseriesMetricType!]) {
  accountMetrics(accountID: $accountID, timeFrame: $timeFrame, groupDevices: true, groupInterfaces: false) {
    from
    to
    sites(siteIDs: $siteIDs) {
      id
      interfaces {
        name
        @INFO@
        timeseries(buckets: $buckets, labels: $labels) { label units data }
      }
    }
  }
}
"""
LINK_METRICS_QUERY = _QUERY.replace("@INFO@", "interfaceInfo { id name }")
# Used when Cato refuses ``interfaceInfo``: links matched by name only.
LINK_METRICS_QUERY_BASIC = _QUERY.replace("@INFO@", "")


def _error(path: str, exc: CatoApiError) -> dict[str, Any]:
    """A refused or failed ``accountMetrics`` query as a collection report
    entry marked ``measurement``: it leaves links without a measurement and
    says nothing about which sites and links exist, so availability
    tracking still removes what the account no longer has
    (``availability.clean_entity_types``)."""
    return {**error_entry("account", path, exc), "measurement": True}


def query_variables(account_id: str, site_ids: list[str], lookback_seconds: int) -> dict[str, Any]:
    """The variables of one query: ``lookback_seconds`` plus the settling
    time, in ``WINDOW_SECONDS`` buckets."""
    span = clamp_lookback(lookback_seconds) + _SETTLE_SECONDS
    return {
        "accountID": account_id,
        "timeFrame": f"last.PT{span // 60}M",
        "siteIDs": site_ids,
        "buckets": span // WINDOW_SECONDS,
        "labels": list(LABELS),
    }


async def collect_link_metrics(
    client: CatoClient,
    account_id: str,
    site_ids: list[str],
    lookback_seconds: int,
    errors: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """``{"granularity": seconds, "sites": [...]}``: the ``accountMetrics``
    sites of ``site_ids``, ``SITES_PER_QUERY`` a query; ``None`` when none
    could be read. A refused or failed query is recorded in ``errors``: a
    refusal of the full query retries without ``interfaceInfo``, and a
    refusal of that stops (the next chunks would be refused too)."""
    sites: list[dict] = []
    answered = False
    query, name = LINK_METRICS_QUERY, "plexusLinkMetrics"
    for offset in range(0, len(site_ids), SITES_PER_QUERY):
        variables = query_variables(account_id, site_ids[offset : offset + SITES_PER_QUERY], lookback_seconds)
        try:
            try:
                data = await client.query(name, query, variables)
            except CatoApiError as exc:
                if not exc.graphql or query is LINK_METRICS_QUERY_BASIC:
                    raise
                errors.append(_error(f"{PATH} (link ids)", exc))
                query, name = LINK_METRICS_QUERY_BASIC, "plexusLinkMetricsBasic"
                data = await client.query(name, query, variables)
        except CatoApiError as exc:
            errors.append(_error(PATH, exc))
            if exc.graphql:
                break
            continue
        answered = True
        found = (data.get("accountMetrics") or {}).get("sites") or []
        sites += [s for s in found if isinstance(s, dict)]
    if not answered:
        return None
    return {"granularity": WINDOW_SECONDS, "read_at": datetime.now(UTC).isoformat(), "sites": sites}


def _buckets(timeseries: Any) -> dict[int, dict[str, float]]:
    """``{bucket start (ms): {label: value}}`` of an interface's
    ``timeseries``; RTT and jitter only in ``ms``, loss only in
    ``percent`` (or no unit given): a series in another unit is left out
    rather than misread."""
    found: dict[int, dict[str, float]] = {}
    for series in timeseries if isinstance(timeseries, list) else []:
        if not isinstance(series, dict) or series.get("label") not in LABELS:
            continue
        units = str(series.get("units") or "").lower()
        if units not in ("", "percent" if str(series["label"]).startswith("lost") else "ms"):
            continue
        for point in series.get("data") or []:
            if not isinstance(point, (list, tuple)) or len(point) != 2:
                continue
            stamp, value = number(point[0]), number(point[1])
            if stamp is None or value is None:
                continue
            found.setdefault(int(stamp), {})[series["label"]] = value
    return found


def _settled_before(raw: dict) -> datetime:
    """Buckets ending after this were not settled when the answer was read."""
    return (parse_time(raw.get("read_at")) or datetime.now(UTC)) - timedelta(seconds=_SETTLE_SECONDS)


def interface_samples(interface: dict, granularity: int, settled_before: datetime) -> list[dict[str, Any]]:
    """The samples (oldest first) of one ``accountMetrics`` interface."""
    found = []
    for stamp, values in sorted(_buckets(interface.get("timeseries")).items()):
        start = datetime.fromtimestamp(stamp / 1000, UTC)
        end = start + timedelta(seconds=granularity)
        if end > settled_before:
            continue
        rtt = values.get("rtt")
        if rtt is None or rtt <= 0:
            continue  # no traffic measured in the bucket
        sample = make_sample(
            start,
            end,
            latency_ms=rtt,
            jitter_ms=worst(values.get(k) for k in ("jitterUpstream", "jitterDownstream")),
            loss_pct=worst(values.get(k) for k in ("lostUpstreamPcnt", "lostDownstreamPcnt")),
        )
        if sample is not None:
            found.append(sample)
    return found


def _key(value: Any) -> str:
    return str(value or "").strip().lower()


class LinkMetrics:
    """The link samples of a collection's ``link_metrics``, looked up by
    site and Socket interface."""

    def __init__(self, raw: Any) -> None:
        self._by_site: dict[str, list[tuple[str, str, str, list[dict]]]] = {}
        if not isinstance(raw, dict):
            return
        granularity = int(number(raw.get("granularity")) or WINDOW_SECONDS)
        settled = _settled_before(raw)
        for site in raw.get("sites") or []:
            if not isinstance(site, dict) or site.get("id") is None:
                continue
            for interface in site.get("interfaces") or []:
                if not isinstance(interface, dict):
                    continue
                found = interface.get("interfaceInfo")
                info: dict = found if isinstance(found, dict) else {}
                samples = interface_samples(interface, granularity, settled)
                if samples:
                    self._by_site.setdefault(str(site["id"]), []).append(
                        (_key(info.get("id")), _key(interface.get("name")), _key(info.get("name")), samples)
                    )

    def for_interface(self, site_id: Any, interface: dict) -> list[dict[str, Any]]:
        """The samples of a Socket interface of ``accountSnapshot`` (its
        ``id``, ``name`` and ``info { id name }``): by id, else by name."""
        entries = self._by_site.get(str(site_id), [])
        found = interface.get("info")
        info: dict = found if isinstance(found, dict) else {}
        ids = {_key(interface.get("id")), _key(info.get("id"))} - {""}
        names = {_key(interface.get("name")), _key(info.get("name"))} - {""}
        for entry_id, *_rest, samples in entries:
            if entry_id and entry_id in ids:
                return samples
        for _id, name, info_name, samples in entries:
            if names & ({name, info_name} - {""}):
                return samples
        return []
