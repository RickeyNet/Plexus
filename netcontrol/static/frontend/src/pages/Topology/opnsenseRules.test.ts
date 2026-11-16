import { describe, expect, it } from 'vitest';

import type { OpnsenseAnalyzedRule, OpnsenseRuleEndpoint } from '@/api/opnsenseRules';

import {
  actionTone,
  changeText,
  countersText,
  endpointText,
  filterRules,
  flagLabel,
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
});
