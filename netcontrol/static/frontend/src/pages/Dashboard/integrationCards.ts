import type { TopologySourceTypeCounts } from '@/api/dashboard';
import { isCloudAccountProvider, type TopologySource } from '@/api/meraki';
import type { Tone } from '@/lib/severity';
import { sourceTypeLabel } from '@/pages/Topology/merakiHelpers';

import { isConnectedSource } from './setupGuide';
import {
  SOURCES_LINK,
  TOPOLOGY_ENTITY_TYPES,
  type AvailabilitySourceRef,
  type SourceHealth,
  classifySourceHealth,
  entityTypeLabel,
  topologyAvailabilityLink,
} from './sourceHealth';

// The Dashboard's Integrations section: one card per connected source with
// its collection health and the state of what it collects (the `by_source`
// rows of the `topology` section of /api/dashboard). Pure, so it is unit
// tested; IntegrationsSection only renders the result.

/**
 * Where a source's availability rows are. A Meraki, Cato, FMC, Panorama or
 * Appgate source is its organization (org_ref = its id). The AWS, Azure and
 * GCP accounts of one cloud are discovered into one snapshot, so their rows
 * share one org_ref: an account maps to every row of its provider. null for
 * a source with no id (neighbor discovery, inventory collection).
 */
export function availabilityRefOf(s: TopologySource): AvailabilitySourceRef | null {
  if (isCloudAccountProvider(s.type)) return { provider: s.type, orgRef: null };
  if (s.id == null) return null;
  return { provider: s.type, orgRef: s.id };
}

export interface EntityTypeCounts {
  type: string;
  /** "VPN connections". */
  label: string;
  up: number;
  degraded: number;
  down: number;
  unknown: number;
  /** Muted down / degraded entities: counted in `total`, never a problem. */
  muted: number;
  total: number;
}

/** The entity types `ref` has, in TOPOLOGY_ENTITY_TYPES order (any other type last, by name). */
export function sourceEntityCounts(
  ref: AvailabilitySourceRef,
  rows: readonly TopologySourceTypeCounts[],
): EntityTypeCounts[] {
  const byType = new Map<string, EntityTypeCounts>();
  for (const r of rows) {
    if (r.provider !== ref.provider) continue;
    if (ref.orgRef != null && r.org_ref !== ref.orgRef) continue;
    const c = byType.get(r.entity_type) ?? {
      type: r.entity_type,
      label: entityTypeLabel(r.entity_type, true),
      up: 0,
      degraded: 0,
      down: 0,
      unknown: 0,
      muted: 0,
      total: 0,
    };
    c.up += r.up;
    c.degraded += r.degraded;
    c.down += r.down;
    c.unknown += r.unknown;
    c.muted += r.muted ?? 0;
    c.total = c.up + c.degraded + c.down + c.unknown + c.muted;
    byType.set(r.entity_type, c);
  }
  const order = (type: string) => {
    const i = TOPOLOGY_ENTITY_TYPES.findIndex((t) => t.key === type);
    return i < 0 ? TOPOLOGY_ENTITY_TYPES.length : i;
  };
  return [...byType.values()]
    .filter((c) => c.total > 0)
    .sort((a, b) => order(a.type) - order(b.type) || a.type.localeCompare(b.type));
}

/** Wording and tone of a collection health verdict. */
export const HEALTH_DISPLAY: Record<SourceHealth, { label: string; tone: Tone }> = {
  healthy: { label: 'OK', tone: 'success' },
  failed: { label: 'Collection failed', tone: 'danger' },
  partial: { label: 'Partial collection', tone: 'warning' },
  stale: { label: 'Overdue', tone: 'warning' },
  warnings: { label: 'Warnings', tone: 'warning' },
  never: { label: 'Never collected', tone: 'neutral' },
};

export interface IntegrationCard {
  key: string;
  source: TopologySource;
  /** "Cato", "AWS". */
  typeLabel: string;
  health: SourceHealth;
  /**
   * What the source collects, per entity type; null when unknown (the user
   * cannot read availability, or the server sends no `by_source`).
   */
  counts: EntityTypeCounts[] | null;
  down: number;
  degraded: number;
  /**
   * Cloud accounts of this provider whose counts are combined into these
   * (more than one: the card says so); 1 for every other source.
   */
  combinedAccounts: number;
  /** The topology map, filtered to this source's provider. */
  mapLink: string;
  /** Monitoring -> Availability filtered to this source; null without counts. */
  availabilityLink: string | null;
  /**
   * The source's availability rows, for links filtered further by type and
   * state (topologyAvailabilityLink); null without counts, like the link.
   */
  availabilityRef: AvailabilitySourceRef | null;
  /** Where to collect a never-collected source. */
  sourcesLink: string;
}

/** Map filtered to one integration (Topology reads `?provider`). */
export function topologyMapLink(provider: string): string {
  return `/topology?${new URLSearchParams({ provider }).toString()}`;
}

// Cards with something wrong first: failed collection or anything down, then
// other trouble, then healthy, then never collected.
function cardRank(c: IntegrationCard): number {
  if (c.health === 'failed' || c.down > 0) return 0;
  if (c.health !== 'healthy' && c.health !== 'never') return 1;
  if (c.degraded > 0) return 1;
  return c.health === 'never' ? 3 : 2;
}

/**
 * One card per connected source (isConnectedSource), worst first, then by
 * provider and name. `bySource` is undefined when the user cannot read
 * availability: the cards then carry collection health only.
 */
export function buildIntegrationCards(
  sources: readonly TopologySource[],
  bySource: readonly TopologySourceTypeCounts[] | undefined,
  now: number = Date.now(),
): IntegrationCard[] {
  const connected = sources.filter(isConnectedSource);
  const accountsOf = (provider: string) => connected.filter((s) => s.type === provider).length;
  const cards = connected.map((s): IntegrationCard => {
    const ref = availabilityRefOf(s);
    const counts = bySource && ref ? sourceEntityCounts(ref, bySource) : null;
    return {
      key: s.key,
      source: s,
      typeLabel: sourceTypeLabel(s.type),
      health: classifySourceHealth(s, now),
      counts,
      down: counts?.reduce((n, c) => n + c.down, 0) ?? 0,
      degraded: counts?.reduce((n, c) => n + c.degraded, 0) ?? 0,
      combinedAccounts: ref && ref.orgRef == null ? accountsOf(s.type) : 1,
      mapLink: topologyMapLink(s.type),
      availabilityLink: counts && ref ? topologyAvailabilityLink(ref) : null,
      availabilityRef: counts && ref ? ref : null,
      sourcesLink: SOURCES_LINK,
    };
  });
  return cards.sort(
    (a, b) =>
      cardRank(a) - cardRank(b) ||
      a.typeLabel.localeCompare(b.typeLabel) ||
      a.source.name.localeCompare(b.source.name),
  );
}

/** "3 up, 1 degraded, 2 down" (zero counts left out, "none" when empty), for screen readers and tooltips. */
export function describeCounts(
  c: Pick<EntityTypeCounts, 'up' | 'degraded' | 'down' | 'unknown'> & { muted?: number },
): string {
  const parts: string[] = [];
  if (c.up) parts.push(`${c.up} up`);
  if (c.degraded) parts.push(`${c.degraded} degraded`);
  if (c.down) parts.push(`${c.down} down`);
  if (c.unknown) parts.push(`${c.unknown} unknown`);
  if (c.muted) parts.push(`${c.muted} muted`);
  return parts.join(', ') || 'none';
}
