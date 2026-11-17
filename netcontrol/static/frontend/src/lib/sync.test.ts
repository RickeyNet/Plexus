import { describe, expect, it } from 'vitest';

import {
  describeSchedule,
  describeTotals,
  diffRows,
  emptyJobDraft,
  formatMappings,
  jobDraftOf,
  parseMappings,
  runTotals,
  toJobInput,
  validateConnection,
  validateJob,
} from './sync';

describe('describeSchedule', () => {
  it('reads minutes as people say them', () => {
    expect(describeSchedule(0)).toBe('Manual only');
    expect(describeSchedule(15)).toBe('Every 15 minutes');
    expect(describeSchedule(60)).toBe('Hourly');
    expect(describeSchedule(180)).toBe('Every 3 hours');
    expect(describeSchedule(1440)).toBe('Daily');
    expect(describeSchedule(2880)).toBe('Every 2 days');
  });
});

describe('parseMappings', () => {
  it('accepts blank and an object keyed by object type', () => {
    expect(parseMappings('  ')).toEqual({ value: {} });
    expect(parseMappings('{"devices": {"role": true, "_endpoint": "dcim/devices"}}')).toEqual({
      value: { devices: { role: true, _endpoint: 'dcim/devices' } },
    });
  });

  it('names what is wrong', () => {
    expect(parseMappings('{')).toEqual({ error: 'Not valid JSON.' });
    expect(parseMappings('[1]')).toHaveProperty('error');
    expect(parseMappings('{"widgets": {}}')).toEqual({ error: 'Unknown object type "widgets".' });
    expect(parseMappings('{"devices": 3}')).toEqual({ error: 'The mapping of devices must be an object.' });
  });

  it('round-trips through the editor text', () => {
    const mappings = { vrfs: { _endpoint: 'u_vrf', rd: false } };
    expect(parseMappings(formatMappings(mappings))).toEqual({ value: mappings });
    expect(formatMappings({})).toBe('');
  });
});

describe('job drafts', () => {
  it('validates the fields the server checks', () => {
    const draft = { ...emptyJobDraft(null), interval: '3', mappingsText: '{"x": {}}', object_types: [] };
    expect(validateJob(draft)).toEqual({
      name: 'Enter a name.',
      connection_id: 'Pick a connection.',
      object_types: 'Pick at least one object type.',
      mappings: 'Unknown object type "x".',
      interval: '0 (manual only) or 5 to 10080 minutes.',
    });
    expect(validateJob({ ...emptyJobDraft(1), name: 'NetBox import', interval: '30' })).toEqual({});
  });

  it('builds the request body in run order and drops deletes for both-ways jobs', () => {
    const draft = {
      ...emptyJobDraft(4),
      name: ' Lab ',
      object_types: ['devices', 'vrfs', 'sites'] as const,
      direction: 'bidirectional' as const,
      delete_missing: true,
      mappingsText: '{"devices": {"role": true}}',
      host_group: '  ',
      interval: '60',
    };
    expect(toJobInput({ ...draft, object_types: [...draft.object_types] })).toEqual({
      name: 'Lab',
      connection_id: 4,
      object_types: ['sites', 'vrfs', 'devices'],
      direction: 'bidirectional',
      conflict_policy: 'skip_conflicts',
      delete_missing: false,
      mappings: { devices: { role: true } },
      host_group: 'Synced',
      interval_minutes: 60,
      enabled: true,
      description: '',
    });
  });

  it('seeds an edit from a stored job', () => {
    const draft = jobDraftOf({
      name: 'CMDB export',
      connection_id: 2,
      object_types: ['devices'],
      direction: 'export',
      conflict_policy: 'plexus_wins',
      delete_missing: true,
      mappings: {},
      options: { host_group: 'Synced / CMDB' },
      interval_minutes: 1440,
      enabled: false,
      description: 'nightly',
    });
    expect(draft).toMatchObject({ mappingsText: '', host_group: 'Synced / CMDB', interval: '1440', enabled: false });
  });
});

describe('validateConnection', () => {
  const ok = { name: 'Lab NetBox', base_url: 'https://netbox.example.com', credential_id: 3, timeout_seconds: 30 };

  it('accepts a complete draft', () => {
    expect(validateConnection(ok)).toEqual({});
  });

  it('refuses plain http, embedded users and missing pieces', () => {
    expect(validateConnection({ ...ok, base_url: 'http://netbox.example.com' }).base_url).toMatch(/https/);
    expect(validateConnection({ ...ok, base_url: 'https://u@netbox.example.com' }).base_url).toMatch(/address only/);
    expect(validateConnection({ ...ok, name: ' ', credential_id: null, timeout_seconds: 1 })).toEqual({
      name: 'Enter a name.',
      credential_id: 'Pick the service credential holding the secret.',
      timeout_seconds: '5 to 300 seconds.',
    });
  });
});

describe('run summaries and diffs', () => {
  it('totals the object types and counts types that failed', () => {
    const totals = runTotals({
      sites: { create: 2, update: 1, unchanged: 5, applied: 3 },
      devices: { create: 1, conflict: 2, failed: 1, skipped: 2 },
      vrfs: { error: 'NetBox answered HTTP 403' },
    });
    expect(totals).toMatchObject({ create: 3, update: 1, conflict: 2, unchanged: 5, applied: 3, failed: 1, errors: 1 });
    expect(describeTotals(totals)).toBe('3 create · 1 update · 2 conflict');
    expect(describeTotals(runTotals({}))).toBe('No changes');
  });

  it('shows before / after, or Plexus / remote for a conflict', () => {
    expect(diffRows({ action: 'update', changes: { rd: { before: '65000:1', after: '65000:2' } } })).toEqual({
      columns: ['Before', 'After'],
      rows: [{ field: 'rd', left: '65000:1', right: '65000:2' }],
    });
    expect(diffRows({ action: 'conflict', changes: { site: { plexus: 'HQ', remote: 'Branch-1' } } })).toEqual({
      columns: ['Plexus', 'Remote'],
      rows: [{ field: 'site', left: 'HQ', right: 'Branch-1' }],
    });
  });
});
