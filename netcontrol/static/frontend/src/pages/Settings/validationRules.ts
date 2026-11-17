import type {
  RuleTestRequest,
  ValidationObjectType,
  ValidationRule,
  ValidationRuleInput,
  ValidationRuleParams,
  ValidationRuleType,
} from '@/api/validationRules';

// Form state and wording of the Validation rules tab (no React).

export const OBJECT_TYPE_LABEL: Record<ValidationObjectType, string> = {
  host: 'Host',
  group: 'Inventory group',
  prefix: 'IPAM prefix',
  ip_address: 'IPAM address',
  vlan: 'VLAN',
  vrf: 'VRF',
};

export const RULE_TYPE_LABEL: Record<ValidationRuleType, string> = {
  regex: 'Matches a pattern',
  length: 'Length',
  numeric: 'Number range',
  required: 'Required',
};

export const RULE_TYPE_HELP: Record<ValidationRuleType, string> = {
  regex:
    'The whole value must match the pattern (case sensitive). Patterns run on RE2: no lookarounds or backreferences.',
  length: 'The value must have at least the minimum and at most the maximum number of characters.',
  numeric: 'The value must be a number from the minimum to the maximum.',
  required: 'The value must not be empty.',
};

export const NAME_MAX = 100;
export const MESSAGE_MAX = 300;
export const PATTERN_MAX = 500;

/** The form: bounds are kept as typed so an empty box means "no bound". */
export interface RuleDraft {
  name: string;
  object_type: ValidationObjectType;
  field: string;
  rule_type: ValidationRuleType;
  pattern: string;
  min: string;
  max: string;
  error_message: string;
  description: string;
  enabled: boolean;
}

export type RuleDraftErrors = Partial<Record<'name' | 'field' | 'pattern' | 'min' | 'max' | 'error_message', string>>;

export function emptyRuleDraft(): RuleDraft {
  return {
    name: '',
    object_type: 'host',
    field: 'hostname',
    rule_type: 'regex',
    pattern: '',
    min: '',
    max: '',
    error_message: '',
    description: '',
    enabled: true,
  };
}

export function toRuleDraft(rule: ValidationRule): RuleDraft {
  return {
    name: rule.name,
    object_type: rule.object_type,
    field: rule.field,
    rule_type: rule.rule_type,
    pattern: rule.params.pattern ?? '',
    min: rule.params.min == null ? '' : String(rule.params.min),
    max: rule.params.max == null ? '' : String(rule.params.max),
    error_message: rule.error_message,
    description: rule.description,
    enabled: rule.enabled,
  };
}

function parseBound(text: string, whole: boolean): number | null | 'invalid' {
  const trimmed = text.trim();
  if (!trimmed) return null;
  const value = Number(trimmed);
  if (!Number.isFinite(value)) return 'invalid';
  if (whole && (!Number.isInteger(value) || value < 0)) return 'invalid';
  return value;
}

/** The parameters of the draft's rule type (bounds as numbers, unset ones left out). */
export function draftParams(draft: RuleDraft): ValidationRuleParams {
  if (draft.rule_type === 'regex') return { pattern: draft.pattern };
  if (draft.rule_type === 'required') return {};
  const whole = draft.rule_type === 'length';
  const params: ValidationRuleParams = {};
  const min = parseBound(draft.min, whole);
  const max = parseBound(draft.max, whole);
  if (typeof min === 'number') params.min = min;
  if (typeof max === 'number') params.max = max;
  return params;
}

/** What the browser can check before sending; the server checks the rest (RE2 syntax). */
export function validateRuleDraft(draft: RuleDraft): RuleDraftErrors {
  const errors: RuleDraftErrors = {};
  const name = draft.name.trim();
  if (!name) errors.name = 'Enter a name.';
  else if (name.length > NAME_MAX) errors.name = `The name must be at most ${NAME_MAX} characters.`;
  if (!draft.field) errors.field = 'Choose a field.';
  if (draft.error_message.trim().length > MESSAGE_MAX) {
    errors.error_message = `The error message must be at most ${MESSAGE_MAX} characters.`;
  }
  if (draft.rule_type === 'regex') {
    if (!draft.pattern) errors.pattern = 'Enter a pattern.';
    else if (draft.pattern.length > PATTERN_MAX) errors.pattern = `The pattern must be at most ${PATTERN_MAX} characters.`;
  }
  if (draft.rule_type === 'length' || draft.rule_type === 'numeric') {
    const whole = draft.rule_type === 'length';
    const what = whole ? 'a whole number of 0 or more' : 'a number';
    const min = parseBound(draft.min, whole);
    const max = parseBound(draft.max, whole);
    if (min === 'invalid') errors.min = `The minimum must be ${what}.`;
    if (max === 'invalid') errors.max = `The maximum must be ${what}.`;
    if (min === null && max === null) errors.min = 'Set a minimum, a maximum or both.';
    if (typeof min === 'number' && typeof max === 'number' && min > max) {
      errors.max = 'The maximum must be at least the minimum.';
    }
  }
  return errors;
}

export function toRuleInput(draft: RuleDraft): ValidationRuleInput {
  return {
    name: draft.name.trim(),
    object_type: draft.object_type,
    field: draft.field,
    rule_type: draft.rule_type,
    params: draftParams(draft),
    error_message: draft.error_message.trim(),
    description: draft.description.trim(),
    enabled: draft.enabled,
  };
}

/** The test request for the rule as the form holds it (saved or not). */
export function toTestRequest(draft: RuleDraft, value: string): RuleTestRequest {
  return {
    rule_type: draft.rule_type,
    params: draftParams(draft),
    field: draft.field,
    error_message: draft.error_message.trim(),
    value,
  };
}

/** Server field errors (`params.pattern`) as the form's own keys. */
export function draftErrorsFromServer(fields: Record<string, string>): RuleDraftErrors {
  const map: Record<string, keyof RuleDraftErrors> = {
    name: 'name',
    field: 'field',
    object_type: 'field',
    'params.pattern': 'pattern',
    'params.min': 'min',
    'params.max': 'max',
    error_message: 'error_message',
  };
  const out: RuleDraftErrors = {};
  for (const [key, message] of Object.entries(fields)) {
    const target = map[key];
    if (target && !out[target]) out[target] = message;
  }
  return out;
}

/** One line saying what a rule checks: "matches sw-[0-9]+", "2 to 64 characters". */
export function describeRule(rule: Pick<ValidationRule, 'rule_type' | 'params'>): string {
  const { min, max, pattern } = rule.params;
  const bounds = min != null && max != null ? `${min} to ${max}` : min != null ? `at least ${min}` : `at most ${max}`;
  switch (rule.rule_type) {
    case 'regex':
      return `matches ${pattern ?? ''}`;
    case 'length':
      return `${bounds} characters`;
    case 'numeric':
      return `a number, ${bounds}`;
    case 'required':
      return 'not empty';
  }
}

/** The label of a rule field, falling back to the raw name (a deleted custom field). */
export function fieldLabel(field: string, fields: { field: string; label: string }[] | undefined): string {
  const found = fields?.find((f) => f.field === field);
  if (found) return found.label;
  return field.startsWith('cf.') ? `${field.slice(3)} (custom field, deleted)` : field;
}
