import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { detailRequest } from './customData';

// Data validation rules (admin only): checks the server runs on host, group,
// IPAM prefix and address, VLAN and VRF writes. See docs/validation-rules.md.
// Failures are CustomDataError, so a 422 names the rule properties it refused.

export type ValidationObjectType = 'host' | 'group' | 'prefix' | 'ip_address' | 'vlan' | 'vrf';
export type ValidationRuleType = 'regex' | 'length' | 'numeric' | 'required';

export interface ValidationRuleParams {
  pattern?: string;
  min?: number;
  max?: number;
}

export interface ValidationRule {
  id: number;
  name: string;
  object_type: ValidationObjectType;
  /** A field of the object (`hostname`) or a custom field (`cf.<key>`). */
  field: string;
  rule_type: ValidationRuleType;
  params: ValidationRuleParams;
  /** Shown when a value breaks the rule; empty: a generated message. */
  error_message: string;
  description: string;
  enabled: boolean;
  created_by: string;
  created_at: string;
  updated_by: string;
  updated_at: string;
}

export interface ValidationRuleInput {
  name: string;
  object_type: ValidationObjectType;
  field: string;
  rule_type: ValidationRuleType;
  params: ValidationRuleParams;
  error_message: string;
  description: string;
  enabled: boolean;
}

export interface RuleField {
  field: string;
  label: string;
  custom: boolean;
}

export interface RuleFieldCatalogue {
  object_types: ValidationObjectType[];
  rule_types: ValidationRuleType[];
  fields: Record<ValidationObjectType, RuleField[]>;
}

export interface Violation {
  field: string;
  rule: string;
  message: string;
}

export interface ViolatingObject {
  object_type: ValidationObjectType;
  object_id: number | null;
  object_key: string;
  label: string;
  violations: Violation[];
}

export interface ViolationReport {
  objects: ViolatingObject[];
  checked: number;
  truncated: boolean;
}

/** A saved rule by id, or an unsaved definition, and the value to check. */
export type RuleTestRequest =
  | { rule_id: number; value: string }
  | {
      rule_type: ValidationRuleType;
      params: ValidationRuleParams;
      field?: string;
      error_message?: string;
      value: string;
    };

export interface RuleTestResult {
  valid: boolean;
  message: string | null;
}

const KEY = ['validation-rules'] as const;

export function useValidationRules() {
  return useQuery<{ rules: ValidationRule[] }>({
    queryKey: KEY,
    queryFn: () => detailRequest('/validation-rules'),
  });
}

export function useRuleFields() {
  return useQuery<RuleFieldCatalogue>({
    queryKey: [...KEY, 'fields'],
    queryFn: () => detailRequest('/validation-rules/fields'),
  });
}

export function useCreateValidationRule() {
  const qc = useQueryClient();
  return useMutation<ValidationRule, Error, ValidationRuleInput>({
    mutationFn: (data) => detailRequest<ValidationRule>('/validation-rules', { method: 'POST', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

export function useUpdateValidationRule() {
  const qc = useQueryClient();
  return useMutation<ValidationRule, Error, { id: number; data: Partial<ValidationRuleInput> }>({
    mutationFn: ({ id, data }) => detailRequest<ValidationRule>(`/validation-rules/${id}`, { method: 'PUT', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

export function useDeleteValidationRule() {
  const qc = useQueryClient();
  return useMutation<{ ok: boolean }, Error, number>({
    mutationFn: (id) => detailRequest(`/validation-rules/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

export function useTestValidationRule() {
  return useMutation<RuleTestResult, Error, RuleTestRequest>({
    mutationFn: (body) => detailRequest<RuleTestResult>('/validation-rules/test', { method: 'POST', body }),
  });
}

/** The stored objects that break enabled rules: run on demand ("Check existing data"). */
export function useCheckExistingData() {
  return useMutation<ViolationReport, Error, ValidationObjectType | null>({
    mutationFn: (objectType) =>
      detailRequest<ViolationReport>(
        `/validation-rules/violations${objectType ? `?object_type=${encodeURIComponent(objectType)}` : ''}`,
      ),
  });
}
