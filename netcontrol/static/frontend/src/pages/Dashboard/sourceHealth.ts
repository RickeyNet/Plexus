import type { TopologyProblem } from '@/api/dashboard';
import type { TopologySource } from '@/api/meraki';
import { parseBackendDate } from '@/lib/datetime';
import { sourceTypeLabel } from '@/pages/Topology/merakiHelpers';

// Health of the topology sources (GET /api/topology/sources) and wording of
// the down / degraded entities they report (the `topology` section of
// /api/dashboard), shared by the CriticalIssuesBanner and the StatRings.

/** Topology page with its Sources dialog open (Topology reads `?sources`). */
export const SOURCES_LINK = '/topology?sources=1';
/** Id of the integrations panel on Monitoring -> Availability. */
export const TOPOLOGY_AVAILABILITY_ANCHOR = 'topology-availability';
export const TOPOLOGY_AVAILABILITY_LINK = `/monitoring/availability#${TOPOLOGY_AVAILABILITY_ANCHOR}`;

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
