import { describe, expect, it, vi } from 'vitest';

import { CustomDataError } from '@/api/customData';
import { runSave } from '@/lib/recordSave';

import {
  contextBody,
  extraParentText,
  generateSummary,
  hostsFromGroups,
  parseContextData,
  parseWeight,
  renderErrorText,
  scopeOptions,
  scopeSummary,
  templateBody,
  templateTextError,
} from './intendedHelpers';

const SCOPE = { device_type: 'cisco_ios', role_id: 2, site_id: 3, group_id: 4 };

describe('templateBody', () => {
  it('sends every writable field, trimmed, with the scope of a device template', () => {
    expect(
      templateBody({ name: '  edge  ', kind: 'device', ...SCOPE, template_text: 'hostname {{ host.name }}\n', description: ' WAN edge ', enabled: false }),
    ).toEqual({
      name: 'edge',
      kind: 'device',
      device_type: 'cisco_ios',
      role_id: 2,
      site_id: 3,
      group_id: 4,
      template_text: 'hostname {{ host.name }}\n',
      description: 'WAN edge',
      enabled: false,
    });
  });

  it('sends no scope for a snippet', () => {
    const body = templateBody({ name: 'ntp', kind: 'snippet', ...SCOPE, template_text: 'ntp server 192.0.2.10\n', description: '', enabled: true });
    expect(body).toMatchObject({ kind: 'snippet', device_type: '', role_id: null, site_id: null, group_id: null });
  });
});

describe('contextBody', () => {
  it('sends the scope, the host and the parsed data', () => {
    expect(
      contextBody({ name: ' ntp ', weight: 1500, ...SCOPE, host_id: 9, description: '', enabled: true }, { ntp: ['192.0.2.10'] }),
    ).toEqual({
      name: 'ntp',
      weight: 1500,
      data: { ntp: ['192.0.2.10'] },
      description: '',
      enabled: true,
      device_type: 'cisco_ios',
      role_id: 2,
      site_id: 3,
      group_id: 4,
      host_id: 9,
    });
  });
});

describe('parseContextData', () => {
  it('blocks text that is not JSON, with the parse error', () => {
    const r = parseContextData('{"ntp": [}');
    expect('error' in r && r.error).toMatch(/^Data is not valid JSON: /);
  });

  it('blocks JSON that is not an object', () => {
    for (const text of ['[1, 2]', '"x"', '42', 'null']) {
      const r = parseContextData(text);
      expect('error' in r && r.error).toBe('Data must be a JSON object (in braces), not a list or a single value.');
    }
    expect('error' in parseContextData('   ')).toBe(true);
  });

  it('reads an object', () => {
    expect(parseContextData('{"syslog": {"host": "198.51.100.5"}}')).toEqual({ data: { syslog: { host: '198.51.100.5' } } });
  });
});

describe('parseWeight', () => {
  it('takes whole numbers from 0 to 100000', () => {
    expect(parseWeight('0')).toBe(0);
    expect(parseWeight(' 1000 ')).toBe(1000);
    expect(parseWeight('100000')).toBe(100000);
    for (const bad of ['', '-1', '1.5', '100001', 'abc']) expect(parseWeight(bad)).toBeNull();
  });
});

describe('errors', () => {
  it('words a template syntax error with its line', () => {
    expect(templateTextError(new CustomDataError("unexpected '}'", 400, {}, null, 3))).toBe("Line 3: unexpected '}'");
    expect(templateTextError(new CustomDataError('Name is required', 400))).toBeNull();
    expect(templateTextError(new CustomDataError('taken', 409))).toBeNull();
  });

  it('words a render error, naming an included template', () => {
    expect(renderErrorText({ message: "'context' has no attribute 'ntp'", template: null, line: 2 })).toBe("Line 2: 'context' has no attribute 'ntp'");
    expect(renderErrorText({ message: 'boom', template: 'edge', line: 4 }, 'edge')).toBe('Line 4: boom');
    expect(renderErrorText({ message: 'boom', template: 'ntp-snippet', line: 1 }, 'edge')).toBe('ntp-snippet: Line 1: boom');
    expect(renderErrorText({ message: 'Render timed out' })).toBe('Render timed out');
  });

  it('shows a syntax error at the field and keeps the dialog open', async () => {
    const setFailure = vi.fn();
    const onClose = vi.fn();
    const shown: string[] = [];
    await runSave(
      () => Promise.reject(new CustomDataError('bad', 400, {}, null, 7)),
      null,
      setFailure,
      onClose,
      (err) => {
        const t = templateTextError(err);
        if (t) shown.push(t);
        return t !== null;
      },
    );
    expect(shown).toEqual(['Line 7: bad']);
    expect(setFailure).toHaveBeenCalledTimes(1);
    expect(setFailure).toHaveBeenCalledWith(null);
    expect(onClose).not.toHaveBeenCalled();
  });
});

describe('summaries', () => {
  it('states what a generation did', () => {
    expect(generateSummary({ hosts: 12, generated: 10, changed: 3, errors: 1, no_template: 2 })).toBe(
      'Generated 10 of 12 hosts: 3 changed, 1 error, 2 hosts without a template.',
    );
    expect(generateSummary({ hosts: 1, generated: 1, changed: 0, errors: 0, no_template: 0 })).toBe('Generated 1 of 1 host: 0 changed, 0 errors.');
  });

  it('places an extra line under its parents', () => {
    expect(extraParentText(['interface Gi0/1', ' ip ospf 1 area 0'])).toBe('interface Gi0/1 › ip ospf 1 area 0');
    expect(extraParentText([])).toBe('Top level');
  });

  it('summarises a scope, marking deleted records', () => {
    const names = { roles: [{ id: 2, name: 'core' }], sites: [], groups: undefined, hosts: [{ id: 9, name: 'edge-1' }] };
    expect(scopeSummary({ device_type: '', role_id: null, site_id: null, group_id: null }, names)).toBe('Any device');
    expect(scopeSummary({ ...SCOPE, host_id: 9 }, names)).toBe('Driver Cisco IOS · Role core · Site (deleted) · Group #4 · Host edge-1');
  });

  it('keeps a deleted scope id selectable as "(deleted)"', () => {
    expect(scopeOptions([{ id: 1, name: 'a' }], 5)).toEqual([
      { id: 1, name: 'a' },
      { id: 5, name: '(deleted)' },
    ]);
    expect(scopeOptions([{ id: 1, name: 'a' }], 1)).toEqual([{ id: 1, name: 'a' }]);
    expect(scopeOptions(undefined, 5)).toEqual([]);
  });

  it('lists each host once by name', () => {
    const groups = [
      { hosts: [{ id: 2, hostname: 'sw10', ip_address: '192.0.2.10' }, { id: 1, hostname: 'sw2', ip_address: '192.0.2.2' }] },
      { hosts: [{ id: 2, hostname: 'sw10', ip_address: '192.0.2.10' }] },
      {},
    ];
    expect(hostsFromGroups(groups).map((h) => h.name)).toEqual(['sw2', 'sw10']);
  });
});
