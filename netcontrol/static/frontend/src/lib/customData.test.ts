import { describe, expect, it } from 'vitest';

import type { CustomField } from '@/api/customData';

import {
  EMPTY_CUSTOM_DATA_FILTER,
  filterCount,
  initialFieldValues,
  isEmptyFilter,
  matchesCustomData,
  missingRequired,
  parseChoices,
  suggestFieldKey,
  tagColorClass,
  toPutFields,
  validateFieldForm,
} from './customData';

const tag = (id: number, name = `t${id}`) => ({ id, name, color: 'gray' });

const field = (key: string, partial: Partial<CustomField> = {}): CustomField => ({
  id: 1,
  key,
  label: key,
  field_type: 'text',
  choices: [],
  object_types: ['host'],
  required: false,
  default_value: '',
  description: '',
  sort_order: 0,
  ...partial,
});

describe('matchesCustomData', () => {
  it('matches every selected tag', () => {
    const row = { tags: [tag(1), tag(2)] };
    expect(matchesCustomData(row, { tagIds: [1, 2], fields: {} })).toBe(true);
    expect(matchesCustomData(row, { tagIds: [1, 3], fields: {} })).toBe(false);
  });

  it('matches field equality and has-value', () => {
    const row = { custom_fields: { env: 'prod' } };
    expect(matchesCustomData(row, { tagIds: [], fields: { env: 'prod' } })).toBe(true);
    expect(matchesCustomData(row, { tagIds: [], fields: { env: 'lab' } })).toBe(false);
    expect(matchesCustomData(row, { tagIds: [], fields: { env: '*' } })).toBe(true);
    expect(matchesCustomData(row, { tagIds: [], fields: { owner: '*' } })).toBe(false);
  });

  it('compares booleans and numbers as text', () => {
    const row = { custom_fields: { managed: true, units: 2 } };
    expect(matchesCustomData(row, { tagIds: [], fields: { managed: 'true' } })).toBe(true);
    expect(matchesCustomData(row, { tagIds: [], fields: { units: '2' } })).toBe(true);
    expect(matchesCustomData(row, { tagIds: [], fields: { managed: 'false' } })).toBe(false);
  });

  it('an empty filter matches everything', () => {
    expect(isEmptyFilter(EMPTY_CUSTOM_DATA_FILTER)).toBe(true);
    expect(filterCount(EMPTY_CUSTOM_DATA_FILTER)).toBe(0);
    expect(matchesCustomData({}, EMPTY_CUSTOM_DATA_FILTER)).toBe(true);
    expect(matchesCustomData({ tags: [tag(1)], custom_fields: { env: 'lab' } }, EMPTY_CUSTOM_DATA_FILTER)).toBe(true);
    expect(filterCount({ tagIds: [1, 2], fields: { env: 'lab' } })).toBe(3);
  });
});

describe('form values', () => {
  it('initial values prefer stored, then default, then empty', () => {
    const fields = [
      field('owner', { default_value: 'net' }),
      field('env', { default_value: 'lab' }),
      field('managed', { field_type: 'boolean', default_value: 'true' }),
      field('note'),
    ];
    expect(initialFieldValues(fields, { owner: 'sec' })).toEqual({
      owner: 'sec',
      env: 'lab',
      managed: true,
      note: '',
    });
  });

  it('sends empty values as null and trims text', () => {
    const fields = [field('owner'), field('units', { field_type: 'number' }), field('managed', { field_type: 'boolean' })];
    expect(toPutFields(fields, { owner: '  net ', units: '', managed: false })).toEqual({
      owner: 'net',
      units: null,
      managed: false,
    });
  });

  it('names each required field with no value', () => {
    const fields = [field('owner', { label: 'Owner', required: true }), field('note', { required: false })];
    expect(missingRequired(fields, { owner: '  ', note: '' })).toEqual({ owner: 'Owner is required.' });
    expect(missingRequired(fields, { owner: 'net', note: '' })).toEqual({});
  });
});

describe('field definitions', () => {
  it('suggests a key from the label', () => {
    expect(suggestFieldKey('Asset owner')).toBe('asset_owner');
    expect(suggestFieldKey('  2nd Circuit ID ')).toBe('nd_circuit_id');
    expect(suggestFieldKey('***')).toBe('');
  });

  it('parses one choice per line', () => {
    expect(parseChoices('prod\n lab \n\nprod\n')).toEqual(['prod', 'lab']);
  });

  it('validates the definition', () => {
    const base = {
      key: 'owner',
      label: 'Owner',
      field_type: 'select' as const,
      choices: ['net'],
      object_types: ['host' as const],
      required: false,
      default_value: 'sec',
      description: '',
      sort_order: 0,
    };
    expect(validateFieldForm(base, true)).toEqual({ default_value: 'The default must be one of the choices.' });
    const errors = validateFieldForm({ ...base, key: 'Owner', label: ' ', choices: [], object_types: [], default_value: '' }, true);
    expect(Object.keys(errors).sort()).toEqual(['choices', 'key', 'label', 'object_types']);
    // The key is fixed after creation, so it is not checked on edit.
    expect(validateFieldForm({ ...base, key: 'Owner', default_value: '' }, false)).toEqual({});
  });

  it('maps a tag color to its chip class', () => {
    expect(tagColorClass('teal')).toBe('tag-chip-teal');
    expect(tagColorClass('magenta')).toBe('tag-chip-gray');
    expect(tagColorClass(undefined)).toBe('tag-chip-gray');
  });
});
