import type { SummarizeOverlap, SummarizeRelation, SummarizeReport, SummarizeRequest, SummarizeRoute } from '@/api/meraki';

import { providerLabel } from './helpers';
import { emptyFilters, filterParams, filtersError, SWEEP_KINDS, type SweepFilters } from './sweep';

// Summarize addresses (`POST /api/topology/summarize`): the fewest routes that
// cover a typed list of addresses, each checked against the collected
// networks the sweep's source filters keep. These helpers turn the form into
// the request and the routes into text; Summarize.tsx draws them.

export interface SummarizeForm extends SweepFilters {
  addresses: string;
  /** Roll up to this prefix length; empty: exact. */
  prefix: string;
  /** At most this many routes of each IP version; empty: no limit. */
  maxRoutes: string;
}

export function emptySummarizeForm(): SummarizeForm {
  return { addresses: '', prefix: '', maxRoutes: '', ...emptyFilters() };
}

/** The form checking against every provider of `providers` but Meraki, every kind of network. */
export function notMerakiForm(form: SummarizeForm, providers: string[]): SummarizeForm {
  return {
    ...form,
    providers: providers.filter((p) => p !== 'meraki'),
    kinds: SWEEP_KINDS.map((k) => k.key),
  };
}

/** A whole number from `low` to `high` typed in `text`; null when empty, undefined when not valid. */
function wholeNumber(text: string, low: number, high: number): number | null | undefined {
  const trimmed = text.trim();
  if (!trimmed) return null;
  if (!/^\d+$/.test(trimmed)) return undefined;
  const value = Number(trimmed);
  return value >= low && value <= high ? value : undefined;
}

/** The request of a form, or the reason it cannot be sent. */
export function buildSummarizeRequest(form: SummarizeForm): { request: SummarizeRequest } | { error: string } {
  const addresses = form.addresses.trim();
  if (!addresses) return { error: 'Enter at least one IP address or network.' };
  const prefix = wholeNumber(form.prefix, 0, 128);
  if (prefix === undefined) return { error: 'Roll up to / must be a prefix length from 0 to 32 (IPv6: 128).' };
  const maxRoutes = wholeNumber(form.maxRoutes, 1, Number.MAX_SAFE_INTEGER);
  if (maxRoutes === undefined) return { error: 'At most N routes must be a whole number of at least 1.' };
  const error = filtersError(form);
  if (error) return { error: `Check overlaps against: ${error}` };
  return { request: { addresses, prefix, max_routes: maxRoutes, ...filterParams(form) } };
}

const RELATION_LABELS: Record<SummarizeRelation, string> = {
  equal: 'equal',
  inside: 'inside the route',
  contains: 'contains the route',
  overlaps: 'overlaps',
};

/** How a collected network lies against its route, in words. */
export function relationLabel(relation: SummarizeRelation | string): string {
  return RELATION_LABELS[relation as SummarizeRelation] ?? relation;
}

/** One overlapping network as `provider · site · name (cidr) relation`, leaving out what it lacks. */
export function overlapText(overlap: SummarizeOverlap): string {
  const where = [overlap.provider ? providerLabel(overlap.provider) : '', overlap.site_name, overlap.name]
    .filter(Boolean)
    .join(' · ');
  return `${where ? `${where} ` : ''}(${overlap.cidr}) ${relationLabel(overlap.relation)}`;
}

/** An address count; one past 2^32 (IPv6 only) roughly, since a number that large is not exact. */
export function addressCount(count: number): string {
  return count > 2 ** 32 ? `≈${count.toExponential(2)}` : count.toLocaleString('en-US');
}

/** The size of a route; an IPv6 route past 2^32 addresses as the power of two it is. */
export function routeSize(route: SummarizeRoute): string {
  const bits = (route.version === 6 ? 128 : 32) - route.prefixlen;
  return bits > 32 ? `2^${bits}` : addressCount(route.addresses);
}

/** The heading of a summary: `3 routes cover 120 addresses (118 unique)`. */
export function summaryHeading(report: SummarizeReport): string {
  const routes = report.route_count === 1 ? '1 route covers' : `${report.route_count} routes cover`;
  const addresses = report.input_count === 1 ? '1 address' : `${report.input_count} addresses`;
  return `${routes} ${addresses} (${report.unique_count} unique)`;
}
