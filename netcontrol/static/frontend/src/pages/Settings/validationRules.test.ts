import { describe, expect, it } from 'vitest';

import type { ValidationRule } from '@/api/validationRules';

import {
  describeRule,
  draftErrorsFromServer,
  draftParams,
  emptyRuleDraft,
  fieldLabel,
  type RuleDraft,
  toRuleDraft,
  toRuleInput,
  toTestRequest,
  validateRuleDraft,
} from './validationRules';

const draft = (patch: Partial<RuleDraft> = {}): RuleDraft => ({ ...emptyRuleDraft(), name: 'naming', ...patch });

const RULE: ValidationRule = {
  id: 1,
  name: 'vid range',
  object_type: 'vlan',
  field: 'vid',
  rule_type: 'numeric',
  params: { min: 100, max: 199 },
  error_message: 'Use 100-199.',
  description: '',
  enabled: false,
  created_by: 'admin',
  created_at: '',
  updated_by: '',
  updated_at: '',
};

describe('validateRuleDraft', () => {
  it('needs a name, a field and a pattern for a regex rule', () => {
    expect(validateRuleDraft(draft({ name: ' ', field: '', pattern: '' }))).toEqual({
      name: 'Enter a name.',
      field: 'Choose a field.',
      pattern: 'Enter a pattern.',
    });
    expect(validateRuleDraft(draft({ pattern: 'sw-[0-9]+' }))).toEqual({});
  });

  it('checks the bounds of length and number rules', () => {
    expect(validateRuleDraft(draft({ rule_type: 'length' })).min).toBe('Set a minimum, a maximum or both.');
    expect(validateRuleDraft(draft({ rule_type: 'length', min: '1.5' })).min).toMatch(/whole number/);
    expect(validateRuleDraft(draft({ rule_type: 'length', min: '-1' })).min).toMatch(/whole number/);
    expect(validateRuleDraft(draft({ rule_type: 'numeric', min: '-1.5' }))).toEqual({});
    expect(validateRuleDraft(draft({ rule_type: 'numeric', max: 'ten' })).max).toMatch(/a number/);
    expect(validateRuleDraft(draft({ rule_type: 'numeric', min: '5', max: '2' })).max).toMatch(/at least the minimum/);
  });

  it('needs nothing more for a required rule', () => {
    expect(validateRuleDraft(draft({ rule_type: 'required' }))).toEqual({});
  });
});

describe('draft conversion', () => {
  it('sends only the parameters of the rule type', () => {
    expect(draftParams(draft({ rule_type: 'regex', pattern: 'a+', min: '3' }))).toEqual({ pattern: 'a+' });
    expect(draftParams(draft({ rule_type: 'length', min: '2', max: '' }))).toEqual({ min: 2 });
    expect(draftParams(draft({ rule_type: 'numeric', min: '', max: '4094' }))).toEqual({ max: 4094 });
    expect(draftParams(draft({ rule_type: 'required', pattern: 'x' }))).toEqual({});
  });

  it('round-trips a stored rule', () => {
    const form = toRuleDraft(RULE);
    expect(form).toMatchObject({ min: '100', max: '199', pattern: '', enabled: false });
    expect(toRuleInput({ ...form, name: '  vid range ', error_message: ' Use 100-199. ' })).toEqual({
      name: 'vid range',
      object_type: 'vlan',
      field: 'vid',
      rule_type: 'numeric',
      params: { min: 100, max: 199 },
      error_message: 'Use 100-199.',
      description: '',
      enabled: false,
    });
  });

  it('builds a test request from the unsaved form', () => {
    expect(toTestRequest(draft({ pattern: 'sw-[0-9]+' }), 'sw-1')).toEqual({
      rule_type: 'regex',
      params: { pattern: 'sw-[0-9]+' },
      field: 'hostname',
      error_message: '',
      value: 'sw-1',
    });
  });

  it('maps server field errors onto the form', () => {
    expect(
      draftErrorsFromServer({ 'params.pattern': 'RE2 refuses lookarounds', object_type: 'bad', unknown: 'x' }),
    ).toEqual({ pattern: 'RE2 refuses lookarounds', field: 'bad' });
  });
});

describe('wording', () => {
  it('describes each rule type', () => {
    expect(describeRule({ rule_type: 'regex', params: { pattern: 'sw-[0-9]+' } })).toBe('matches sw-[0-9]+');
    expect(describeRule({ rule_type: 'length', params: { min: 2, max: 64 } })).toBe('2 to 64 characters');
    expect(describeRule({ rule_type: 'length', params: { max: 64 } })).toBe('at most 64 characters');
    expect(describeRule({ rule_type: 'numeric', params: { min: 1 } })).toBe('a number, at least 1');
    expect(describeRule({ rule_type: 'required', params: {} })).toBe('not empty');
  });

  it('labels fields, including a deleted custom field', () => {
    const fields = [{ field: 'cf.owner', label: 'Owner' }];
    expect(fieldLabel('cf.owner', fields)).toBe('Owner');
    expect(fieldLabel('cf.site_code', fields)).toBe('site_code (custom field, deleted)');
    expect(fieldLabel('hostname', undefined)).toBe('hostname');
  });
});
