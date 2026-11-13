import { describe, expect, it } from 'vitest';

import type { TopologyProblem } from '@/api/dashboard';
import type { TopologySource } from '@/api/meraki';

import {
  STALE_FALLBACK_MS,
  classifySourceHealth,
  describeProblem,
  isSourceStale,
  isTrackedSource,
  matchesAvailabilityState,
  muteBadgeTitle,
  muteEntityChoiceLabel,
  parseAvailabilityState,
  problemLocation,
  sourceLabel,
  staleAfterMs,
  summarizeSources,
  unmuteConfirmMessage,
} from './sourceHealth';

const NOW = Date.parse('2026-03-10T12:00:00Z');
const HOUR = 60 * 60 * 1000;

function iso(msBeforeNow: number): string {
  return new Date(NOW - msBeforeNow).toISOString();
}

function source(over: Partial<TopologySource> = {}): TopologySource {
  return {
    key: 'org:1',
    type: 'meraki',
    id: 1,
    name: 'Example Org',
    status: 'success',
    last_collected_at: iso(HOUR / 2),
    message: '',
    detail: '',
    warning_count: 0,
    collecting: false,
    can_collect: true,
    enabled: true,
    demo: false,
    ...over,
  };
}

function problem(over: Partial<TopologyProblem> = {}): TopologyProblem {
  return {
    provider: 'cato',
    provider_label: 'Cato',
    org_ref: 11,
    org_name: 'Example account',
    entity_type: 'tunnel',
    type_label: 'Tunnel',
    entity_id: 't1',
    name: 'Tunnel 1',
    site: 'Branch A',
    host_id: null,
    state: 'down',
    raw_status: 'down',
    since: '2026-03-10 11:00:00',
    ...over,
  };
}

describe('isTrackedSource', () => {
  it('skips disabled and demo sources', () => {
    expect(isTrackedSource(source())).toBe(true);
    expect(isTrackedSource(source({ enabled: false }))).toBe(false);
    expect(isTrackedSource(source({ demo: true }))).toBe(false);
  });
});

describe('staleAfterMs', () => {
  it('is twice the scheduled interval, read from the last and next collection', () => {
    const s = source({ last_collected_at: iso(HOUR), next_collection_at: iso(-HOUR) });
    expect(staleAfterMs(s)).toBe(4 * HOUR);
  });
  it('reads a backend stamp without a zone as UTC', () => {
    const s = source({ last_collected_at: '2026-03-10 10:00:00', next_collection_at: '2026-03-10T13:00:00+00:00' });
    expect(staleAfterMs(s)).toBe(6 * HOUR);
  });
  it('falls back to the constant without a schedule', () => {
    expect(staleAfterMs(source({ type: 'aws' }))).toBe(STALE_FALLBACK_MS);
    expect(staleAfterMs(source({ next_collection_at: null }))).toBe(STALE_FALLBACK_MS);
    // A next collection that is not after the last one says nothing about the interval.
    expect(staleAfterMs(source({ last_collected_at: iso(HOUR), next_collection_at: iso(HOUR) }))).toBe(
      STALE_FALLBACK_MS,
    );
  });
  it('never applies to a source opted out of scheduled collection', () => {
    expect(staleAfterMs(source({ auto_collect: false }))).toBeNull();
  });
});

describe('isSourceStale', () => {
  it('compares the age of the last collection with the threshold', () => {
    const scheduled = { next_collection_at: iso(-HOUR / 2) }; // hourly: last 30 min ago, next in 30 min
    expect(isSourceStale(source({ last_collected_at: iso(HOUR / 2), ...scheduled }), NOW)).toBe(false);
    // Overdue: collected 3h ago on an hourly schedule (next was due 2h ago).
    expect(isSourceStale(source({ last_collected_at: iso(3 * HOUR), next_collection_at: iso(2 * HOUR) }), NOW)).toBe(
      true,
    );
    expect(isSourceStale(source({ type: 'azure', last_collected_at: iso(23 * HOUR) }), NOW)).toBe(false);
    expect(isSourceStale(source({ type: 'azure', last_collected_at: iso(25 * HOUR) }), NOW)).toBe(true);
    expect(isSourceStale(source({ auto_collect: false, last_collected_at: iso(100 * HOUR) }), NOW)).toBe(false);
  });
  it('is never stale without a collection', () => {
    expect(isSourceStale(source({ last_collected_at: null }), NOW)).toBe(false);
  });
});

describe('classifySourceHealth', () => {
  it('picks the worst verdict that applies', () => {
    const old = iso(48 * HOUR);
    expect(classifySourceHealth(source({ status: 'failed', last_collected_at: old, warning_count: 3 }), NOW)).toBe(
      'failed',
    );
    expect(classifySourceHealth(source({ status: 'partial', last_collected_at: old, warning_count: 3 }), NOW)).toBe(
      'partial',
    );
    expect(classifySourceHealth(source({ last_collected_at: old, warning_count: 3 }), NOW)).toBe('stale');
    expect(classifySourceHealth(source({ warning_count: 3 }), NOW)).toBe('warnings');
    expect(classifySourceHealth(source(), NOW)).toBe('healthy');
  });
  it('has nothing to judge before the first collection', () => {
    expect(classifySourceHealth(source({ status: 'never', last_collected_at: null }), NOW)).toBe('never');
    // A first collection that failed is still a failure.
    expect(classifySourceHealth(source({ status: 'failed', last_collected_at: null }), NOW)).toBe('failed');
  });
});

describe('summarizeSources', () => {
  it('buckets tracked sources and leaves out disabled, demo and never-collected ones', () => {
    const failed = source({ key: 'a', status: 'failed' });
    const partial = source({ key: 'b', status: 'partial' });
    const stale = source({ key: 'c', type: 'gcp', last_collected_at: iso(30 * HOUR) });
    const warned = source({ key: 'd', warning_count: 2 });
    const summary = summarizeSources(
      [
        failed,
        partial,
        stale,
        warned,
        source({ key: 'e' }),
        source({ key: 'f', status: 'failed', enabled: false }),
        source({ key: 'g', status: 'failed', demo: true }),
        source({ key: 'h', status: 'never', last_collected_at: null }),
      ],
      NOW,
    );
    expect(summary.total).toBe(5);
    expect(summary.healthy).toBe(1);
    expect(summary.failed).toEqual([failed]);
    expect(summary.partial).toEqual([partial]);
    expect(summary.stale).toEqual([stale]);
    expect(summary.warnings).toEqual([warned]);
  });
  it('is empty for no sources', () => {
    expect(summarizeSources([], NOW)).toEqual({ total: 0, healthy: 0, failed: [], partial: [], stale: [], warnings: [] });
  });
});

describe('availability state filter', () => {
  it("'muted' matches only muted entities", () => {
    expect(matchesAvailabilityState({ current_state: 'down', muted: true }, 'muted')).toBe(true);
    expect(matchesAvailabilityState({ current_state: 'up', muted: true }, 'muted')).toBe(true);
    expect(matchesAvailabilityState({ current_state: 'down', muted: false }, 'muted')).toBe(false);
    // An older server sends no flag: nothing is muted.
    expect(matchesAvailabilityState({ current_state: 'down' }, 'muted')).toBe(false);
  });
  it("'problem' leaves a muted down entity out", () => {
    expect(matchesAvailabilityState({ current_state: 'down', muted: true }, 'problem')).toBe(false);
    expect(matchesAvailabilityState({ current_state: 'degraded', muted: true }, 'degraded')).toBe(false);
    expect(matchesAvailabilityState({ current_state: 'down', muted: true }, 'down')).toBe(false);
    expect(matchesAvailabilityState({ current_state: 'down', muted: false }, 'problem')).toBe(true);
    // Up and unknown match by state, muted or not.
    expect(matchesAvailabilityState({ current_state: 'up', muted: true }, 'up')).toBe(true);
    expect(matchesAvailabilityState({ current_state: 'unknown', muted: true }, 'unknown')).toBe(true);
  });
  it("parses 'muted' from the query string", () => {
    expect(parseAvailabilityState('muted')).toBe('muted');
  });
});

describe('mute wording', () => {
  it('names the entity type of the single-entity choice', () => {
    expect(muteEntityChoiceLabel('device')).toBe('This device only');
    expect(muteEntityChoiceLabel('uplink')).toBe('This uplink only');
    expect(muteEntityChoiceLabel('vpn_connection')).toBe('This VPN connection only');
  });
  it('says a site unmute covers the whole site', () => {
    expect(unmuteConfirmMessage('Branch-12 MX', { scope: 'entity' }, 'Branch-12')).toBe('Unmute Branch-12 MX?');
    expect(unmuteConfirmMessage('Branch-12 MX', { scope: 'site' }, 'Branch-12')).toBe(
      'Unmute Branch-12 MX?\nThis unmutes everything at site Branch-12.',
    );
    // A tunnel stored under the hub's site, muted through the branch site.
    expect(unmuteConfirmMessage('Hub - Branch-12', { scope: 'site', site: 'Branch-12' }, 'Hub')).toBe(
      'Unmute Hub - Branch-12?\nThis unmutes everything at site Branch-12.',
    );
  });
  it('titles the Muted badge with reason, who and when', () => {
    const title = muteBadgeTitle({ reason: 'Not installed yet', created_by: 'alice', created_at: '2026-11-13 10:00:00' });
    expect(title.startsWith('Not installed yet - alice, ')).toBe(true);
    expect(title).toContain('2026');
  });
});

describe('labels', () => {
  it('names a source by its type label', () => {
    expect(sourceLabel(source({ type: 'fmc', name: 'Lab FMC' }))).toBe('Cisco FMC: Lab FMC');
    expect(sourceLabel(source({ type: 'inventory', name: '' }))).toBe('Inventory');
  });
  it('describes a down entity with its site and organization', () => {
    expect(problemLocation(problem())).toBe('at Branch A (Example account)');
    expect(describeProblem(problem())).toBe('Cato Tunnel Tunnel 1 at Branch A (Example account)');
    // A site entity is its own site.
    const site = problem({ entity_type: 'site', type_label: 'Site', name: 'Branch A', org_name: '' });
    expect(describeProblem(site)).toBe('Cato Site Branch A');
  });
});
