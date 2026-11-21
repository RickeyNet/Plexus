import { describe, expect, it } from 'vitest';

import type { OpnsenseAnalyzedRule, OpnsenseRuleEndpoint } from '@/api/opnsenseRules';

import {
  actionTone,
  aliasTableLines,
  changeText,
  countersText,
  endpointText,
  filterRules,
  findingText,
  flagLabel,
  flagName,
  historyLines,
  isOpnsenseDevice,
} from './opnsenseRules';

function side(text: string, extra: Partial<OpnsenseRuleEndpoint> = {}): OpnsenseRuleEndpoint {
  return {
    text,
    port: 'any',
    any: text === 'any',
    negate: false,
    cidrs: text === 'any' ? ['any'] : ['192.0.2.0/25'],
    ports: 'any',
    aliases: [],
    missing_aliases: [],
    unresolved: [],
    ...extra,
  };
}

function rule(number: number, extra: Partial<OpnsenseAnalyzedRule> = {}): OpnsenseAnalyzedRule {
  return {
    number,
    key: `k${number}`,
    uuid: '',
    tier: 'interface',
    action: 'pass',
    interfaces: ['lan'],
    zones: ['lan'],
    direction: 'in',
    family: 'inet',
    protocol: 'tcp',
    quick: true,
    disabled: false,
    description: `rule ${number}`,
    gateway: '',
    log: false,
    source: side('lan net'),
    destination: side('WebServers', { port: '443', aliases: ['WebServers'], cidrs: ['192.0.2.140/32'] }),
    unresolved: [],
    flags: [],
    shadowed_by: null,
    shadow: '',
    missing_aliases: [],
    stats: null,
    ...extra,
  };
}

describe('opnsense rules helpers', () => {
  it('knows an OPNsense device type', () => {
    expect(isOpnsenseDevice('opnsense')).toBe(true);
    expect(isOpnsenseDevice('cisco_ios')).toBe(false);
    expect(isOpnsenseDevice(undefined)).toBe(false);
  });

  it('labels flags with the rule that shadows and the missing aliases', () => {
    const shadowed = rule(5, { flags: ['shadowed'], shadowed_by: 2, shadow: 'conflicting' });
    expect(flagLabel(shadowed, 'shadowed')).toBe('Shadowed by #2 (opposite action)');
    const missing = rule(6, { flags: ['missing_alias'], missing_aliases: ['OldPartners'] });
    expect(flagLabel(missing, 'missing_alias')).toBe('Missing alias: OldPartners');
    expect(flagLabel(rule(7), 'any_any')).toBe('Any to any');
  });

  it('filters by interface, flag and text; floating rules show on every interface', () => {
    const rules = [
      rule(1, { zones: ['*'], tier: 'floating' }),
      rule(2),
      rule(3, { zones: ['opt1'], flags: ['unused'] }),
    ];
    expect(filterRules(rules, { iface: 'opt1', flag: '', text: '' }).map((r) => r.number)).toEqual([1, 3]);
    expect(filterRules(rules, { iface: '', flag: 'unused', text: '' }).map((r) => r.number)).toEqual([3]);
    expect(filterRules(rules, { iface: '', flag: '', text: 'webservers' }).map((r) => r.number)).toEqual([1, 2, 3]);
    expect(filterRules(rules, { iface: '', flag: '', text: '192.0.2.140' })).toHaveLength(3);
    expect(filterRules(rules, { iface: 'lan', flag: '', text: 'nothing like it' })).toEqual([]);
  });

  it('formats sides, counters, actions and changes', () => {
    expect(endpointText(side('WebServers', { port: '443' }))).toBe('WebServers port 443');
    expect(endpointText(side('any'))).toBe('any');
    expect(countersText(rule(1, { stats: { packets: 1200, states: 3 } }))).toBe(
      `${(1200).toLocaleString()} pkts · 3 states`,
    );
    expect(countersText(rule(1))).toBe('');
    expect(actionTone('pass')).toBe('success');
    expect(actionTone('reject')).toBe('danger');
    expect(changeText(['lan', 'opt1'])).toBe('lan, opt1');
    expect(changeText(true)).toBe('yes');
    expect(changeText('')).toBe('-');
  });

  it('names the aliases resolved from a collected pf table, with their size', () => {
    const point = side('Partners, GeoBlock', { aliases: ['Partners', 'geoblock', 'WebServers'] });
    const tables = {
      read_at: '2026-11-14 09:00:10',
      tables: {
        Partners: { entry_count: 1, total: 1, truncated: false },
        GeoBlock: { entry_count: 9999, total: 50000, truncated: true },
      },
    };
    expect(aliasTableLines(point, tables)).toEqual([
      'Partners: pf table, 1 entry',
      `geoblock: pf table, truncated, ${(9999).toLocaleString()} of ${(50000).toLocaleString()} entries read`,
    ]);
    expect(aliasTableLines(point, undefined)).toEqual([]);
  });

  it('tells a rule change finding of a backup comparison', () => {
    const finding = {
      kind: 'any_any' as const,
      key: 'k7',
      number: 7,
      interfaces: ['lan'],
      action: 'pass',
      protocol: 'any',
      source: 'any',
      source_port: 'any',
      destination: 'any',
      destination_port: 'any',
      description: 'temporary',
      shadowed_by: null,
      shadow: '' as const,
    };
    expect(findingText(finding)).toBe('any to any: #7 pass any → any temporary');
    expect(
      findingText({
        ...finding,
        kind: 'shadowed',
        action: 'block',
        source: 'lan net',
        destination: 'WebServers',
        destination_port: '443',
        description: '',
        shadowed_by: 2,
        shadow: 'conflicting',
      }),
    ).toBe('shadowed by #2 (conflicting): #7 block lan net → WebServers port 443');
  });

  it('names the long-term unused flag by the server threshold and tells the counter history', () => {
    const history = {
      first_seen_at: '2026-06-01 08:00:00',
      last_seen_at: '2026-11-14 08:00:00',
      last_hit_at: null,
      tracked_days: 166,
      idle_days: 166,
      total_packets: 0,
      total_bytes: 0,
    };
    expect(flagName('unused_90d', 90)).toBe('Unused 90 days');
    expect(flagName('unused_90d', undefined)).toBe('Unused long-term');
    expect(flagName('unused', 90)).toBe('Unused');
    const idle = rule(4, { flags: ['unused_90d'], history });
    expect(flagLabel(idle, 'unused_90d')).toBe('No hit in 166 days');
    expect(historyLines(idle, 90)).toEqual(['no hit since tracking began', 'tracked for 166 days']);
    const young = rule(5, {
      history: { ...history, last_hit_at: '2026-11-13 08:00:00', tracked_days: 30, idle_days: 1 },
    });
    expect(historyLines(young, 90)).toEqual(['last hit 1 day ago', 'tracked for 30 days (60 days before the 90-day check)']);
    expect(historyLines(rule(6, { history: { ...history, last_hit_at: '2026-11-14 08:00:00', idle_days: 0 } }), 90)[0]).toBe(
      'last hit today',
    );
    expect(historyLines(rule(7), 90)).toEqual([]);
    expect(filterRules([idle, young], { iface: '', flag: 'unused_90d', text: '' }).map((r) => r.number)).toEqual([4]);
  });
});
