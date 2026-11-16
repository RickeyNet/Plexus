import { describe, expect, it } from 'vitest';

import {
  cellText,
  formBody,
  initialFormValues,
  pluginApiPath,
  pluginNavEntries,
  pluginPageRoute,
  refreshSources,
  tableRows,
  type PluginBlock,
  type PluginEntry,
  type PluginFormBlock,
  type PluginFormField,
} from './plugins';

const field = (name: string, extra: Partial<PluginFormField> = {}): PluginFormField => ({
  name,
  label: name.toUpperCase(),
  type: 'text',
  required: false,
  options: [],
  help: '',
  ...extra,
});

const entry = (name: string, extra: Partial<PluginEntry> = {}): PluginEntry => ({
  name,
  label: name,
  version: '1.0.0',
  description: '',
  status: 'active',
  feature: `plugin:${name}`,
  navigation: [{ label: 'Spares', page: 'spares' }],
  pages: [],
  ...extra,
});

describe('plugin paths', () => {
  it('keeps data paths under the plugin API', () => {
    expect(pluginApiPath('example', 'spares')).toBe('/plugins/example/spares');
    expect(pluginPageRoute('example', 'spares')).toBe('/plugins/example/spares');
  });
});

describe('tableRows', () => {
  it('accepts a list or an items list and drops non-objects', () => {
    expect(tableRows([{ a: 1 }, 'x', null, [1]])).toEqual([{ a: 1 }]);
    expect(tableRows({ items: [{ a: 2 }] })).toEqual([{ a: 2 }]);
    expect(tableRows({ rows: [] })).toEqual([]);
    expect(tableRows('nope')).toEqual([]);
  });
});

describe('cellText', () => {
  it('renders values as plain text', () => {
    expect(cellText(null)).toBe('');
    expect(cellText(true)).toBe('Yes');
    expect(cellText(3)).toBe('3');
    expect(cellText({ a: 1 })).toBe('{"a":1}');
    expect(cellText('<b>x</b>')).toBe('<b>x</b>');
  });
});

describe('form values', () => {
  const fields = [
    field('part', { required: true }),
    field('quantity', { type: 'number' }),
    field('spare', { type: 'checkbox' }),
    field('kind', { type: 'select', required: true, options: ['psu', 'fan'] }),
  ];

  it('starts empty, with a required select on its first option', () => {
    expect(initialFormValues(fields)).toEqual({ part: '', quantity: '', spare: false, kind: 'psu' });
  });

  it('builds a typed JSON body', () => {
    expect(formBody(fields, { part: ' PSU ', quantity: '4', spare: true, kind: 'fan' })).toEqual({
      body: { part: 'PSU', quantity: 4, spare: true, kind: 'fan' },
    });
  });

  it('leaves an empty optional number out and names a missing required field', () => {
    expect(formBody(fields, { part: 'x', quantity: '', spare: false, kind: 'psu' })).toEqual({
      body: { part: 'x', spare: false, kind: 'psu' },
    });
    expect(formBody(fields, { part: '  ', quantity: '', spare: false, kind: 'psu' })).toEqual({ missing: 'PART' });
    expect(formBody(fields, { part: 'x', quantity: 'abc', spare: false, kind: 'psu' })).toEqual({ missing: 'QUANTITY' });
  });
});

describe('refreshSources', () => {
  it('maps refreshed table ids to their sources', () => {
    const form: PluginFormBlock = {
      type: 'form',
      id: 'f',
      title: '',
      submit: 'spares',
      method: 'POST',
      submit_label: 'Save',
      fields: [field('part')],
      refreshes: ['t1'],
    };
    const blocks: PluginBlock[] = [
      form,
      { type: 'table', id: 't1', title: '', source: 'spares', columns: [], empty_text: '' },
      { type: 'table', id: 't2', title: '', source: 'other', columns: [], empty_text: '' },
    ];
    expect(refreshSources(form, blocks)).toEqual(['spares']);
  });
});

describe('pluginNavEntries', () => {
  it('lists the entries of active plugins only', () => {
    const manifest = {
      admin: true,
      plugins: [entry('example'), entry('broken', { status: 'failed' }), entry('off', { status: 'disabled' })],
    };
    expect(pluginNavEntries(manifest)).toEqual([
      { key: 'example/spares', label: 'Spares', to: '/plugins/example/spares', feature: 'plugin:example' },
    ]);
    expect(pluginNavEntries(undefined)).toEqual([]);
  });
});
