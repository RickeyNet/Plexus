import { describe, expect, it } from 'vitest';

import type { SyslogRule } from '@/api/syslogRules';

import {
  conditionLabel,
  EMPTY_TRAP_RULE_FORM,
  parseVarbindLines,
  trapBodyFromForm,
  trapFormFromRule,
  trapInstanceLabel,
} from './syslogRules';

// Invented rule: the enterprise OID 1.3.6.1.4.1.32473 is the documentation
// enterprise number (RFC 5612).
const TRAP_RULE: SyslogRule = {
  id: 12,
  key: 'custom_12',
  source: 'trap',
  metric: 'trap_custom_12',
  name: 'Disk filling',
  description: '',
  builtin: false,
  enabled: true,
  severity: 'critical',
  match_type: 'trap',
  pattern: '1.3.6.1.4.1.32473.2.0.5',
  clear_pattern: '1.3.6.1.4.1.32473.2.0.6',
  tags: [],
  clear_tags: [],
  families: [],
  threshold_count: 1,
  threshold_window_seconds: 300,
  auto_resolve_minutes: 0,
  created_by: 'ops',
  created_at: '',
  updated_at: '',
  trap_match: {
    conditions: [{ object: '1.3.6.1.4.1.32473.1.3.1.3', op: 'equals', value: 'high' }],
    clear_conditions: [],
    instance: { object: '1.3.6.1.4.1.32473.1.3.1.2', part: 'value' },
  },
};

describe('trap rule form', () => {
  it('round-trips a stored rule', () => {
    const form = trapFormFromRule(TRAP_RULE);
    expect(form.instance_object).toBe('1.3.6.1.4.1.32473.1.3.1.2');
    expect(trapBodyFromForm(form)).toEqual({
      name: 'Disk filling',
      enabled: true,
      severity: 'critical',
      threshold_count: 1,
      threshold_window_seconds: 300,
      auto_resolve_minutes: 0,
      pattern: '1.3.6.1.4.1.32473.2.0.5',
      clear_pattern: '1.3.6.1.4.1.32473.2.0.6',
      trap_match: TRAP_RULE.trap_match,
    });
  });

  it('defaults a rule without trap_match to one alert per device', () => {
    const form = trapFormFromRule({ ...TRAP_RULE, trap_match: undefined });
    expect([form.conditions, form.instance_object, form.instance_part]).toEqual([[], '', 'value']);
  });

  it('drops empty condition rows, and clearing conditions without a clearing trap', () => {
    const body = trapBodyFromForm({
      ...EMPTY_TRAP_RULE_FORM,
      name: ' Link ',
      pattern: ' linkDown ',
      threshold_count: 'x',
      conditions: [
        { object: ' ifAdminStatus ', op: 'equals', value: ' up ' },
        { object: '', op: 'equals', value: '' },
      ],
      clear_conditions: [{ object: 'ifOperStatus', op: 'equals', value: 'up' }],
    });
    expect(body.name).toBe('Link');
    expect(body.pattern).toBe('linkDown');
    expect(body.threshold_count).toBe(1);
    expect(body.trap_match.conditions).toEqual([{ object: 'ifAdminStatus', op: 'equals', value: 'up' }]);
    expect(body.trap_match.clear_conditions).toEqual([]);
    expect(body.trap_match.instance).toEqual({ object: '', part: 'value' });
  });
});

describe('trap rule labels', () => {
  it('names a condition and the instance', () => {
    expect(conditionLabel({ object: 'ifDescr', op: 'regex', value: '^Gi' })).toBe('ifDescr matches (RE2) ^Gi');
    expect(conditionLabel({ object: 'ifDescr', op: 'contains', value: 'Gi' })).toBe('ifDescr contains Gi');
    expect(trapInstanceLabel(undefined)).toBe('Per device');
    expect(trapInstanceLabel({ conditions: [], clear_conditions: [], instance: { object: 'ifIndex', part: 'index' } })).toBe(
      'Index of ifIndex',
    );
    expect(trapInstanceLabel(TRAP_RULE.trap_match)).toBe('Value of 1.3.6.1.4.1.32473.1.3.1.2');
  });
});

describe('trap tester varbinds', () => {
  it('reads one varbind per line, OID = value or OID value', () => {
    expect(parseVarbindLines('1.3.6.1.2.1.2.2.1.1.12 = 12\n\n  1.3.6.1.2.1.2.2.1.2.12   Gi1/0/12 uplink \n1.3.6.1.2.1.1.5.0\nx = a = b')).toEqual([
      ['1.3.6.1.2.1.2.2.1.1.12', '12'],
      ['1.3.6.1.2.1.2.2.1.2.12', 'Gi1/0/12 uplink'],
      ['1.3.6.1.2.1.1.5.0', ''],
      ['x', 'a = b'],
    ]);
    expect(parseVarbindLines('')).toEqual([]);
  });
});
