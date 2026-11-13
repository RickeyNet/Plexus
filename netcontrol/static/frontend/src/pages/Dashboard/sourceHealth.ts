import type { TopologyProblem } from '@/api/dashboard';
import type { TopologySource } from '@/api/meraki';
import type { TopologyMute, TopologyMuteCreate, TopologyMuteTarget } from '@/api/monitoring';
import { formatBackendDateTime, parseBackendDate } from '@/lib/datetime';
import { sourceTypeLabel } from '@/pages/Topology/merakiHelpers';

// Health of the topology sources (GET /api/topology/sources) and wording of
// the down / degraded entities they report (the `topology` section of
// /api/dashboard), shared by the CriticalIssuesBanner and the StatRings.

/** Topology page with its Sources dialog open (Topology reads `?sources`). */
export const SOURCES_LINK = '/topology?sources=1';
/** Id of the integrations panel on Monitoring -> Availability. */
export const TOPOLOGY_AVAILABILITY_ANCHOR = 'topology-availability';
export const TOPOLOGY_AVAILABILITY_LINK = `/monitoring/availability#${TOPOLOGY_AVAILABILITY_ANCHOR}`;
/** Query parameter of that panel naming the source it opens filtered to. */
export const AVAILABILITY_SOURCE_PARAM = 'source';
/** Query parameter of that panel naming the entity type it opens filtered to. */
export const AVAILABILITY_TYPE_PARAM = 'type';
/** Query parameter of that panel naming the current state its entities are filtered to. */
export const AVAILABILITY_STATE_PARAM = 'state';

/**
 * A current state the panel's entities can be filtered to; `problem` is down
 * or degraded, `muted` is every muted entity whatever its state.
 */
export type AvailabilityStateFilter = 'problem' | 'down' | 'degraded' | 'up' | 'unknown' | 'muted';

/** The state filters, in the panel's order, with their labels. */
export const AVAILABILITY_STATE_FILTERS: readonly { key: AvailabilityStateFilter; label: string }[] = [
  { key: 'problem', label: 'Down or degraded' },
  { key: 'down', label: 'Down' },
  { key: 'degraded', label: 'Degraded' },
  { key: 'up', label: 'Up' },
  { key: 'unknown', label: 'Unknown' },
  { key: 'muted', label: 'Muted' },
];

/** Reads the `?state=` value; null when absent or not one of AVAILABILITY_STATE_FILTERS. */
export function parseAvailabilityState(value: string | null | undefined): AvailabilityStateFilter | null {
  return AVAILABILITY_STATE_FILTERS.find((f) => f.key === value)?.key ?? null;
}

/**
 * Whether an entity is in the set `filter` names. A muted entity is never a
 * problem (as on the server, which leaves it out of the down and degraded
 * counts); up and unknown match by state alone.
 */
export function matchesAvailabilityState(
  entity: { current_state: string; muted?: boolean },
  filter: AvailabilityStateFilter,
): boolean {
  const state = entity.current_state;
  const muted = entity.muted === true;
  switch (filter) {
    case 'muted':
      return muted;
    case 'problem':
      return !muted && (state === 'down' || state === 'degraded');
    case 'down':
    case 'degraded':
      return !muted && state === filter;
    default:
      return state === filter;
  }
}

/** Longest mute reason the server accepts. */
export const MUTE_REASON_MAX = 500;

/** A reason the server accepts: 1 to MUTE_REASON_MAX characters once trimmed. */
export function isMuteReasonValid(reason: string): boolean {
  const n = reason.trim().length;
  return n > 0 && n <= MUTE_REASON_MAX;
}

/** "This device only", "This VPN connection only". */
export function muteEntityChoiceLabel(entityType: string): string {
  const label = entityTypeLabel(entityType);
  // Lower-case a plain word ("Tunnel"), not an acronym ("VPN connection").
  const word = /^[A-Z][a-z]/.test(label) ? label[0].toLowerCase() + label.slice(1) : label;
  return `This ${word} only`;
}

/** The POST /availability/topology/mutes body for muting `target` (or its site). */
export function muteRequestBody(
  target: TopologyMuteTarget,
  scope: TopologyMute['scope'],
  reason: string,
): TopologyMuteCreate {
  const base = { provider: target.provider, org_ref: target.org_ref, reason: reason.trim() };
  return scope === 'site'
    ? { ...base, scope, site: target.site }
    : { ...base, scope, entity_type: target.entity_type, entity_id: target.entity_id };
}

/**
 * Sends a mute and calls `onDone` once it is stored. Resolves to null on
 * success, else to the error message, for the dialog to show while it stays open.
 */
export async function submitMute(
  post: (body: TopologyMuteCreate) => Promise<unknown>,
  body: TopologyMuteCreate,
  onDone: () => void,
): Promise<string | null> {
  try {
    await post(body);
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
  onDone();
  return null;
}

/** "Not installed yet - alice, Nov 13, 2026, 10:00 AM", the title of a Muted badge. */
export function muteBadgeTitle(mute: Pick<TopologyMute, 'reason' | 'created_by' | 'created_at'>): string {
  return `${mute.reason} - ${mute.created_by}, ${formatBackendDateTime(mute.created_at)}`;
}

/**
 * The message of the Unmute confirm; a site mute says it covers the whole
 * site. `site` is the entity's, used when the mute does not name its own.
 */
export function unmuteConfirmMessage(
  name: string,
  mute: Pick<TopologyMute, 'scope'> & { site?: string },
  site: string,
): string {
  const question = `Unmute ${name}?`;
  return mute.scope === 'site' ? `${question}\nThis unmutes everything at site ${mute.site || site}.` : question;
}

/** What else the panel opens filtered to, besides the source. */
export interface AvailabilityFilter {
  entityType?: string | null;
  state?: AvailabilityStateFilter | null;
}

/**
 * The availability rows of one source: its provider and org_ref, or every
 * org_ref of the provider when `orgRef` is null (the AWS, Azure and GCP
 * accounts of one cloud are recorded together).
 */
export interface AvailabilitySourceRef {
  provider: string;
  orgRef: number | null;
}

/**
 * The integrations panel on Monitoring -> Availability, filtered to `ref`
 * (every source when absent) and to `filter`'s entity type and state.
 */
export function topologyAvailabilityLink(ref?: AvailabilitySourceRef | null, filter: AvailabilityFilter = {}): string {
  const params = new URLSearchParams();
  if (ref) params.set(AVAILABILITY_SOURCE_PARAM, ref.orgRef == null ? ref.provider : `${ref.provider}:${ref.orgRef}`);
  if (filter.entityType) params.set(AVAILABILITY_TYPE_PARAM, filter.entityType);
  if (filter.state) params.set(AVAILABILITY_STATE_PARAM, filter.state);
  const query = params.toString();
  return query ? `/monitoring/availability?${query}#${TOPOLOGY_AVAILABILITY_ANCHOR}` : TOPOLOGY_AVAILABILITY_LINK;
}

/** Reads the `?source=` value topologyAvailabilityLink writes; null when absent or malformed. */
export function parseAvailabilitySource(value: string | null | undefined): AvailabilitySourceRef | null {
  const m = /^([a-z0-9_-]+)(?::(-?\d+))?$/i.exec((value ?? '').trim());
  if (!m) return null;
  return { provider: m[1].toLowerCase(), orgRef: m[2] != null ? parseInt(m[2], 10) : null };
}

/** Entity types the availability tracking records, in display order. */
export const TOPOLOGY_ENTITY_TYPES: readonly { key: string; label: string; plural: string }[] = [
  { key: 'device', label: 'Device', plural: 'Devices' },
  { key: 'site', label: 'Site', plural: 'Sites' },
  { key: 'uplink', label: 'Uplink', plural: 'Uplinks' },
  { key: 'tunnel', label: 'Tunnel', plural: 'Tunnels' },
  { key: 'vpn_connection', label: 'VPN connection', plural: 'VPN connections' },
  { key: 'circuit', label: 'Circuit', plural: 'Circuits' },
  { key: 'peering', label: 'Peering', plural: 'Peerings' },
  { key: 'link', label: 'Link', plural: 'Links' },
];

/** Reads the `?type=` value; null when absent or not one of TOPOLOGY_ENTITY_TYPES. */
export function parseAvailabilityEntityType(value: string | null | undefined): string | null {
  return TOPOLOGY_ENTITY_TYPES.find((t) => t.key === value)?.key ?? null;
}

/** "VPN connection"; an unknown type as it is. */
export function entityTypeLabel(type: string, plural = false): string {
  const t = TOPOLOGY_ENTITY_TYPES.find((e) => e.key === type);
  if (!t) return type;
  return plural ? t.plural : t.label;
}

/**
 * How old the last collection of a source may get before it counts as stale
 * when its schedule is unknown. The collection schedule
 * (GET /api/sources/schedule) is admin-only, so the Dashboard never reads it:
 * a scheduled source's interval is the gap between its `last_collected_at`
 * and `next_collection_at`, and anything else (cloud accounts, neighbor
 * discovery, inventory collection, scheduling switched off) falls back to
 * this.
 */
export const STALE_FALLBACK_MS = 24 * 60 * 60 * 1000;

export type SourceHealth = 'healthy' | 'failed' | 'partial' | 'stale' | 'warnings' | 'never';

/** A source the Dashboard judges: switched on and not a bundled demo. */
export function isTrackedSource(s: TopologySource): boolean {
  return s.enabled !== false && !s.demo;
}

/**
 * Milliseconds after its last collection that a source turns stale: twice
 * its scheduled interval when it has one, else STALE_FALLBACK_MS. null when
 * it never does: it opted out of scheduled collection, so an old collection
 * is expected.
 */
export function staleAfterMs(s: TopologySource): number | null {
  if (s.auto_collect === false) return null;
  const last = parseBackendDate(s.last_collected_at);
  const next = parseBackendDate(s.next_collection_at);
  if (last && next) {
    const interval = next.getTime() - last.getTime();
    if (interval > 0) return 2 * interval;
  }
  return STALE_FALLBACK_MS;
}

/** Whether a source that has collected before is overdue for a collection. */
export function isSourceStale(s: TopologySource, now: number = Date.now()): boolean {
  const last = parseBackendDate(s.last_collected_at);
  if (!last) return false;
  const after = staleAfterMs(s);
  return after != null && now - last.getTime() > after;
}

/**
 * One verdict per source, the worst that applies: a failed or partial last
 * collection, then stale, then warnings. `never` is a source with nothing
 * collected to judge.
 */
export function classifySourceHealth(s: TopologySource, now: number = Date.now()): SourceHealth {
  if (s.status === 'failed') return 'failed';
  if (s.status === 'partial') return 'partial';
  if (s.status === 'never' || !s.last_collected_at) return 'never';
  if (isSourceStale(s, now)) return 'stale';
  if ((s.warning_count ?? 0) > 0) return 'warnings';
  return 'healthy';
}

export interface SourceHealthSummary {
  /** Tracked sources that have collected (or tried to) at least once. */
  total: number;
  healthy: number;
  failed: TopologySource[];
  partial: TopologySource[];
  stale: TopologySource[];
  warnings: TopologySource[];
}

/** Tracked sources by verdict; disabled, demo and never-collected ones are left out. */
export function summarizeSources(
  sources: readonly TopologySource[],
  now: number = Date.now(),
): SourceHealthSummary {
  const out: SourceHealthSummary = { total: 0, healthy: 0, failed: [], partial: [], stale: [], warnings: [] };
  for (const s of sources) {
    if (!isTrackedSource(s)) continue;
    const health = classifySourceHealth(s, now);
    if (health === 'never') continue;
    out.total += 1;
    if (health === 'healthy') out.healthy += 1;
    else out[health].push(s);
  }
  return out;
}

/** "Cato: Example account", for chip tooltips. */
export function sourceLabel(s: TopologySource): string {
  return s.name ? `${sourceTypeLabel(s.type)}: ${s.name}` : sourceTypeLabel(s.type);
}

/** Where a down / degraded entity is: its site (when not itself) and organization / account. */
export function problemLocation(p: TopologyProblem): string {
  const parts: string[] = [];
  if (p.site && p.site !== p.name) parts.push(`at ${p.site}`);
  if (p.org_name) parts.push(`(${p.org_name})`);
  return parts.join(' ');
}

/** "Cato Tunnel Tunnel C at Branch A (Example account)", for tooltips. */
export function describeProblem(p: TopologyProblem): string {
  const where = problemLocation(p);
  return `${p.provider_label} ${p.type_label} ${p.name}${where ? ` ${where}` : ''}`;
}
