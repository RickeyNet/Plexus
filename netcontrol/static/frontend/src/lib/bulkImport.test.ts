import { describe, expect, it } from 'vitest';

import {
  actionTone,
  buildImportForm,
  canCommit,
  changeList,
  errorText,
  filterRows,
  formatFromFileName,
  IMPORT_TYPES,
  importPath,
  type ImportRow,
  inputProblem,
  MAX_IMPORT_BYTES,
  reportFromErrorBody,
  summaryText,
} from './bulkImport';

const summary = (s: Partial<Record<'create' | 'update' | 'skip' | 'error' | 'total', number>>) => ({
  summary: { create: 0, update: 0, skip: 0, error: 0, total: 0, ...s },
});

const ROWS: ImportRow[] = [
  { row: 2, key: 'edge-sw1', action: 'create', errors: [], changes: {}, warnings: [] },
  {
    row: 3,
    key: 'edge-sw2',
    action: 'update',
    errors: [],
    changes: { 'IP Address': { before: '192.0.2.1', after: '192.0.2.2' }, Role: { before: '', after: 'Switch' } },
    warnings: [],
  },
  {
    row: 4,
    key: 'edge-sw3',
    action: 'error',
    errors: [
      { field: 'group', message: "No group 'lab'." },
      { field: '', message: 'The row has more cells than the header has columns.' },
    ],
    changes: {},
    warnings: [],
  },
];

describe('importPath', () => {
  it('puts each type under its family', () => {
    expect(importPath('hosts', 'preview')).toBe('/import/inventory/hosts/preview');
    expect(importPath('groups', 'commit')).toBe('/import/inventory/groups/commit');
    expect(importPath('vlans', 'template')).toBe('/import/ipam/vlans/template');
    expect(IMPORT_TYPES.prefixes.family).toBe('ipam');
  });

  it('defaults the match key to the first one', () => {
    expect(IMPORT_TYPES.hosts.matchKeys.map((m) => m.key)).toEqual(['hostname', 'ip']);
  });
});

describe('formatFromFileName', () => {
  it('reads the extension, ignoring case', () => {
    expect(formatFromFileName('inventory_export.csv')).toBe('csv');
    expect(formatFromFileName('hosts.YML')).toBe('yaml');
    expect(formatFromFileName('hosts.yaml')).toBe('yaml');
    expect(formatFromFileName('hosts.json')).toBe('json');
    expect(formatFromFileName('hosts.xlsx')).toBeNull();
    expect(formatFromFileName('hosts')).toBeNull();
  });
});

describe('inputProblem', () => {
  it('needs a file or text, within the size limit', () => {
    expect(inputProblem({ file: null, text: '  ' })).toMatch(/Choose a file/);
    expect(inputProblem({ file: null, text: 'Hostname\nsw1' })).toBeNull();
    expect(inputProblem({ file: new File(['a'], 'a.csv'), text: '' })).toBeNull();
    const big = new File([new Uint8Array(MAX_IMPORT_BYTES + 1)], 'big.csv');
    expect(inputProblem({ file: big, text: '' })).toMatch(/larger than 1 MiB/);
    expect(inputProblem({ file: null, text: 'x'.repeat(MAX_IMPORT_BYTES + 1) })).toMatch(/larger/);
  });
});

describe('buildImportForm', () => {
  it('sends the pasted text and the options', () => {
    const form = buildImportForm({ file: null, text: 'a,b', format: 'csv', mode: 'upsert', matchKey: 'ip' });
    expect(form.get('text')).toBe('a,b');
    expect(form.get('file')).toBeNull();
    expect(form.get('format')).toBe('csv');
    expect(form.get('mode')).toBe('upsert');
    expect(form.get('match_key')).toBe('ip');
    expect(form.get('atomic')).toBeNull();
  });

  it('sends the file instead of text, and atomic for a commit', () => {
    const file = new File(['- hostname: sw1'], 'hosts.yaml');
    const form = buildImportForm({ file, text: 'ignored', format: 'yaml', mode: 'create', matchKey: '', atomic: false });
    expect((form.get('file') as File).name).toBe('hosts.yaml');
    expect(form.get('text')).toBeNull();
    expect(form.get('atomic')).toBe('false');
  });
});

describe('summaryText and canCommit', () => {
  it('describes what the import would do', () => {
    expect(summaryText(summary({ create: 2, update: 1, total: 3 }))).toBe('3 rows: 2 to create, 1 to update.');
    expect(summaryText(summary({ create: 1, skip: 2, error: 1, total: 4 }))).toBe(
      '4 rows: 1 to create, 0 to update, 2 unchanged or skipped, 1 row with errors.',
    );
  });

  it('commits only with something to write and, all or nothing, no errors', () => {
    expect(canCommit(summary({ create: 1, total: 1 }), true)).toBe(true);
    expect(canCommit(summary({ create: 1, error: 1, total: 2 }), true)).toBe(false);
    expect(canCommit(summary({ create: 1, error: 1, total: 2 }), false)).toBe(true);
    expect(canCommit(summary({ skip: 3, total: 3 }), true)).toBe(false);
  });
});

describe('rows', () => {
  it('filters by action', () => {
    expect(filterRows(ROWS, 'all')).toHaveLength(3);
    expect(filterRows(ROWS, 'error').map((r) => r.row)).toEqual([4]);
    expect(filterRows(ROWS, 'skip')).toEqual([]);
  });

  it('lists an update diff and the errors', () => {
    expect(changeList(ROWS[1])).toEqual([
      { field: 'IP Address', before: '192.0.2.1', after: '192.0.2.2' },
      { field: 'Role', before: '', after: 'Switch' },
    ]);
    expect(errorText(ROWS[2])).toBe("group: No group 'lab'.; The row has more cells than the header has columns.");
  });

  it('tones each action', () => {
    expect(actionTone('create')).toBe('success');
    expect(actionTone('update')).toBe('info');
    expect(actionTone('skip')).toBe('neutral');
    expect(actionTone('error')).toBe('danger');
  });
});

describe('reportFromErrorBody', () => {
  it('reads the report of a refused commit and nothing else', () => {
    const body = { ...summary({ error: 1, total: 1 }), rows: [ROWS[2]], committed: false, message: 'Nothing was imported' };
    expect(reportFromErrorBody(body)?.message).toBe('Nothing was imported');
    expect(reportFromErrorBody({ ok: false, error: { message: 'x' } })).toBeNull();
    expect(reportFromErrorBody(null)).toBeNull();
    expect(reportFromErrorBody('text')).toBeNull();
  });
});
