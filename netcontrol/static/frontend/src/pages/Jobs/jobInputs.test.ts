import { describe, expect, it } from 'vitest';

import type { JobInputField } from '@/api/jobs';

import {
  buildInputsPayload,
  emptyRow,
  fieldFromRow,
  formatJobInputs,
  isCidr,
  isIpAddress,
  normalizeSecretName,
  rowFromField,
  seedInputValues,
  validateInputs,
  validateInputValue,
  validateSchemaRows,
} from './jobInputs';

const f = (over: Partial<JobInputField> & Pick<JobInputField, 'name' | 'type'>): JobInputField => ({
  label: over.name,
  ...over,
});

describe('address formats', () => {
  it('accepts IPv4 and IPv6 addresses', () => {
    expect(isIpAddress('192.0.2.10')).toBe(true);
    expect(isIpAddress('2001:db8::1')).toBe(true);
    expect(isIpAddress('192.0.2.300')).toBe(false);
    expect(isIpAddress('192.0.2.01')).toBe(false);
    expect(isIpAddress('example.com')).toBe(false);
  });

  it('accepts prefixes in CIDR form only', () => {
    expect(isCidr('198.51.100.0/24')).toBe(true);
    expect(isCidr('2001:db8::/32')).toBe(true);
    expect(isCidr('198.51.100.0')).toBe(false);
    expect(isCidr('198.51.100.0/33')).toBe(false);
    expect(isCidr('198.51.100.0/24/1')).toBe(false);
  });

  it('reduces a pasted secret reference to the name', () => {
    expect(normalizeSecretName(' {{secret.snmp_key}} ')).toBe('snmp_key');
    expect(normalizeSecretName('secret.snmp_key')).toBe('snmp_key');
  });
});

describe('validateInputValue', () => {
  it('requires a required field unless it has a default', () => {
    expect(validateInputValue(f({ name: 'vlan', type: 'integer', required: true }), '')).toBe('vlan is required.');
    expect(validateInputValue(f({ name: 'vlan', type: 'integer', required: true, default: 10 }), '')).toBeNull();
    expect(validateInputValue(f({ name: 'opt', type: 'string' }), '  ')).toBeNull();
  });

  it('checks integers and their bounds', () => {
    const vlan = f({ name: 'vlan', type: 'integer', min: 2, max: 4094 });
    expect(validateInputValue(vlan, '1.5')).toMatch(/whole number/);
    expect(validateInputValue(vlan, '1')).toMatch(/at least 2/);
    expect(validateInputValue(vlan, '5000')).toMatch(/at most 4094/);
    expect(validateInputValue(vlan, '120')).toBeNull();
  });

  it('checks string length and pattern', () => {
    const s = f({ name: 'descr', type: 'string', regex: '[a-z-]+', max: 10 });
    expect(validateInputValue(s, 'uplink')).toBeNull();
    expect(validateInputValue(s, 'Uplink')).toMatch(/required format/);
    expect(validateInputValue(s, 'aaaaaaaaaaa')).toMatch(/at most 10/);
  });

  it('checks choices, lists and object pickers', () => {
    expect(validateInputValue(f({ name: 'm', type: 'choice', choices: ['a'] }), 'b')).toMatch(/one of: a/);
    expect(validateInputValue(f({ name: 'm', type: 'multichoice', choices: ['a', 'b'] }), ['a', 'c'])).toMatch(/'c'/);
    expect(validateInputValue(f({ name: 'm', type: 'multichoice', choices: ['a', 'b'], max: 1 }), ['a', 'b'])).toMatch(/at most 1 item/);
    expect(validateInputValue(f({ name: 'l', type: 'list', min: 2 }), 'one')).toMatch(/at least 2 item/);
    expect(validateInputValue(f({ name: 'h', type: 'host' }), '0')).toMatch(/must be selected/);
    expect(validateInputValue(f({ name: 'h', type: 'host' }), '12')).toBeNull();
  });

  it('checks addresses and secret names', () => {
    expect(validateInputValue(f({ name: 'ip', type: 'ip' }), 'nope')).toMatch(/IP address/);
    expect(validateInputValue(f({ name: 'net', type: 'cidr' }), '192.0.2.1')).toMatch(/CIDR/);
    expect(validateInputValue(f({ name: 'k', type: 'secret' }), '{{secret.snmp_key}}')).toBeNull();
    expect(validateInputValue(f({ name: 'k', type: 'secret' }), 'bad name')).toMatch(/secret variable/);
  });

  it('refuses secret references outside secret fields', () => {
    expect(validateInputValue(f({ name: 's', type: 'string' }), 'x {{secret.k}}')).toMatch(/secret references/);
    expect(validateInputValue(f({ name: 'l', type: 'list' }), '{{secret.k}}')).toMatch(/secret references/);
  });
});

describe('form values and payload', () => {
  const schema: JobInputField[] = [
    f({ name: 'vlan', type: 'integer', required: true }),
    f({ name: 'on', type: 'boolean', default: true }),
    f({ name: 'tags', type: 'multichoice', choices: ['a', 'b'], default: ['a'] }),
    f({ name: 'ifs', type: 'list', default: ['Gi0/1', 'Gi0/2'] }),
    f({ name: 'host', type: 'host' }),
    f({ name: 'key', type: 'secret' }),
    f({ name: 'note', type: 'string' }),
  ];

  it('seeds defaults', () => {
    expect(seedInputValues(schema)).toEqual({
      vlan: '',
      on: true,
      tags: ['a'],
      ifs: 'Gi0/1, Gi0/2',
      host: '',
      key: '',
      note: '',
    });
  });

  it('collects one error per bad field', () => {
    expect(Object.keys(validateInputs(schema, { ...seedInputValues(schema), host: 'x' }))).toEqual(['vlan', 'host']);
  });

  it('builds typed inputs and leaves empty fields to the server', () => {
    const values = { ...seedInputValues(schema), vlan: '120', host: '7', key: '{{secret.snmp_key}}', ifs: 'a, b, a' };
    expect(buildInputsPayload(schema, values)).toEqual({
      vlan: 120,
      on: true,
      tags: ['a'],
      ifs: ['a', 'b'],
      host: 7,
      key: 'snmp_key',
    });
  });
});

describe('formatJobInputs', () => {
  it('shows hosts by name and secrets by reference', () => {
    const raw = JSON.stringify({
      vlan: 120,
      host: { id: 7, hostname: 'sw-lab-1', ip_address: '192.0.2.7' },
      key: '{{secret.snmp_key}}',
      ifs: ['Gi0/1', 'Gi0/2'],
    });
    expect(formatJobInputs(raw)).toBe('vlan=120; host=sw-lab-1; key=secret snmp_key; ifs=Gi0/1, Gi0/2');
    expect(formatJobInputs(null)).toBe('');
    expect(formatJobInputs('not json')).toBe('');
  });
});

describe('schema editor rows', () => {
  it('round-trips a field through a row', () => {
    const field = f({ name: 'vlan', type: 'integer', label: 'VLAN', required: true, default: 10, min: 2, max: 4094 });
    expect(fieldFromRow(rowFromField(field))).toEqual({ ...field, help: '' });
    const choice = f({ name: 'mode', type: 'multichoice', choices: ['a', 'b'], default: ['a'] });
    expect(fieldFromRow(rowFromField(choice))).toMatchObject({ choices: ['a', 'b'], default: ['a'] });
  });

  it('drops attributes a type does not use', () => {
    const row = { ...emptyRow(), name: 'flag', type: 'boolean' as const, choices: 'x', min: '1', regex: 'a', default: 'true' };
    expect(fieldFromRow(row)).toEqual({ name: 'flag', type: 'boolean', label: 'flag', help: '', required: false, default: true });
  });

  it('flags bad rows keyed like the server', () => {
    const rows = [
      { ...emptyRow(), name: 'ok' },
      { ...emptyRow(), name: '1bad' },
      { ...emptyRow(), name: 'pick', type: 'choice' as const },
      { ...emptyRow(), name: 'n', type: 'integer' as const, min: '5', max: '1' },
      { ...emptyRow(), name: 'pat', regex: '(' },
      { ...emptyRow(), name: 'd', type: 'integer' as const, default: 'x' },
      { ...emptyRow(), name: 'h', type: 'host' as const, default: '3' },
      { ...emptyRow(), name: 'ok' },
    ];
    expect(Object.keys(validateSchemaRows(rows)).sort()).toEqual(
      ['1.name', '2.choices', '3.max', '4.regex', '5.default', '6.default', '7.name'].sort(),
    );
  });
});
