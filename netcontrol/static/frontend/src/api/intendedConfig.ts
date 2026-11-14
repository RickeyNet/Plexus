/**
 * Intended configuration under /api/intended-config: Jinja2 templates and
 * config contexts scoped to devices, each host's rendered intended
 * configuration and how it compares with the host's newest backup. Failures
 * throw a `CustomDataError`: a template syntax error is a 400 whose `line`
 * names the line, a taken name a 409.
 */
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { detailRequest, listOf } from './customData';

export type TemplateKind = 'device' | 'snippet';
export type IntendedStatus = 'ok' | 'error';
export type IntendedCompliance = 'compliant' | 'non_compliant' | 'unknown';

/** Which devices a template or context applies to. `''` / null: any. */
export interface IntendedScope {
  /** Driver key (`cisco_ios`...), `''` for any. */
  device_type: string;
  role_id: number | null;
  site_id: number | null;
  group_id: number | null;
}

export interface ConfigTemplate extends IntendedScope {
  id: number;
  name: string;
  kind: TemplateKind | string;
  template_text: string;
  description: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
  updated_by: string;
  /** Hosts whose stored intended configuration came from this template. */
  host_count: number;
}

/** A template create or full replace. Snippets carry an empty scope. */
export interface ConfigTemplateInput extends IntendedScope {
  name: string;
  kind: TemplateKind;
  template_text: string;
  description: string;
  enabled: boolean;
}

export interface ConfigContext extends IntendedScope {
  id: number;
  name: string;
  weight: number;
  data: Record<string, unknown>;
  description: string;
  enabled: boolean;
  host_id: number | null;
  created_at: string;
  updated_at: string;
  updated_by: string;
}

export interface ConfigContextInput extends IntendedScope {
  name: string;
  weight: number;
  data: Record<string, unknown>;
  description: string;
  enabled: boolean;
  host_id: number | null;
}

export interface RenderError {
  message: string;
  /** The template the error is in, when Jinja names one. */
  template?: string | null;
  line?: number | null;
}

export interface PreviewRequest {
  host_id: number;
  template_id?: number;
  /** Wins over `template_id`. */
  template_text?: string;
}

export interface PreviewResult {
  template_name: string | null;
  config_text: string;
  error: RenderError | null;
}

export interface HostVariables {
  variables: Record<string, unknown>;
  /** The contexts merged for the host, in merge order. */
  contexts: { id: number; name: string; weight: number }[];
}

export interface IntendedRow {
  host_id: number;
  hostname: string;
  ip_address: string;
  group_id: number | null;
  group_name: string | null;
  template_id: number | null;
  template_name: string;
  status: IntendedStatus | string;
  error: string | null;
  compliance: IntendedCompliance | string;
  missing_count: number;
  extra_count: number;
  backup_id: number | null;
  generated_at: string | null;
  changed_at: string | null;
  compared_at: string | null;
}

export interface IntendedCounts {
  hosts: number;
  generated: number;
  errors: number;
  compliant: number;
  non_compliant: number;
  unknown: number;
  no_template: number;
}

export interface IntendedHosts {
  rows: IntendedRow[];
  counts: IntendedCounts;
}

export interface IntendedLine {
  text: string;
  /** The device's backup lacks this line. */
  missing: boolean;
}

/** A backup line the intended configuration lacks, under its parent lines. */
export interface IntendedExtraLine {
  path: string[];
  text: string;
}

export interface IntendedDetail extends IntendedRow {
  config_text: string;
  lines: IntendedLine[];
  extra: IntendedExtraLine[];
  backup: { id: number; captured_at: string } | null;
}

export interface GenerateRequest {
  host_ids?: number[];
  group_id?: number;
}

export interface GenerateResult {
  hosts: number;
  generated: number;
  changed: number;
  errors: number;
  no_template: number;
}

/** The Devices view's server-side filters; '' / null: no filter. */
export interface IntendedHostFilter {
  group_id: number | null;
  compliance: IntendedCompliance | '';
  status: IntendedStatus | '';
}

const BASE = '/intended-config';

/** The host list URL with only the filters that are set. */
export function intendedHostsPath(filter: IntendedHostFilter): string {
  const params = new URLSearchParams();
  if (filter.group_id !== null) params.set('group_id', String(filter.group_id));
  if (filter.compliance) params.set('compliance', filter.compliance);
  if (filter.status) params.set('status', filter.status);
  const qs = params.toString();
  return `${BASE}/hosts${qs ? `?${qs}` : ''}`;
}

/**
 * One call per route; the hooks below wrap them. Exported so tests can check
 * the method, URL and body each sends.
 */
export const intendedConfigApi = {
  templates: async () => listOf<ConfigTemplate>(await detailRequest(`${BASE}/templates`), 'templates'),
  template: (id: number) => detailRequest<ConfigTemplate>(`${BASE}/templates/${id}`),
  createTemplate: (data: ConfigTemplateInput) => detailRequest<ConfigTemplate>(`${BASE}/templates`, { method: 'POST', body: data }),
  updateTemplate: (id: number, data: ConfigTemplateInput) =>
    detailRequest<ConfigTemplate>(`${BASE}/templates/${id}`, { method: 'PUT', body: data }),
  deleteTemplate: (id: number) => detailRequest<{ ok: boolean }>(`${BASE}/templates/${id}`, { method: 'DELETE' }),
  contexts: async () => listOf<ConfigContext>(await detailRequest(`${BASE}/contexts`), 'contexts'),
  context: (id: number) => detailRequest<ConfigContext>(`${BASE}/contexts/${id}`),
  createContext: (data: ConfigContextInput) => detailRequest<ConfigContext>(`${BASE}/contexts`, { method: 'POST', body: data }),
  updateContext: (id: number, data: ConfigContextInput) =>
    detailRequest<ConfigContext>(`${BASE}/contexts/${id}`, { method: 'PUT', body: data }),
  deleteContext: (id: number) => detailRequest<{ ok: boolean }>(`${BASE}/contexts/${id}`, { method: 'DELETE' }),
  preview: (body: PreviewRequest) => detailRequest<PreviewResult>(`${BASE}/preview`, { method: 'POST', body }),
  variables: (hostId: number) => detailRequest<HostVariables>(`${BASE}/hosts/${hostId}/variables`),
  hosts: (filter: IntendedHostFilter) => detailRequest<IntendedHosts>(intendedHostsPath(filter)),
  host: (hostId: number) => detailRequest<IntendedDetail>(`${BASE}/hosts/${hostId}`),
  generate: (body: GenerateRequest) => detailRequest<GenerateResult>(`${BASE}/generate`, { method: 'POST', body }),
};

export const INTENDED_CONFIG_QUERY_ROOT = ['intended-config'] as const;
const ROOT = INTENDED_CONFIG_QUERY_ROOT;
export const INTENDED_CONFIG_KEYS = {
  templates: [...ROOT, 'templates'] as const,
  template: (id: number) => [...ROOT, 'template', id] as const,
  contexts: [...ROOT, 'contexts'] as const,
  context: (id: number) => [...ROOT, 'context', id] as const,
  hosts: (filter: IntendedHostFilter) => [...ROOT, 'hosts', filter] as const,
  host: (hostId: number) => [...ROOT, 'host', hostId] as const,
  variables: (hostId: number) => [...ROOT, 'variables', hostId] as const,
};

type QC = ReturnType<typeof useQueryClient>;

/** Templates, contexts, the rows, details and variables all move together. */
function invalidateAll(qc: QC) {
  qc.invalidateQueries({ queryKey: ROOT });
}

export function useIntendedTemplates() {
  return useQuery<ConfigTemplate[]>({
    queryKey: INTENDED_CONFIG_KEYS.templates,
    queryFn: intendedConfigApi.templates,
  });
}

export function useIntendedTemplate(id: number | null) {
  return useQuery<ConfigTemplate>({
    queryKey: INTENDED_CONFIG_KEYS.template(id ?? 0),
    queryFn: () => intendedConfigApi.template(id!),
    enabled: id !== null,
  });
}

export function useIntendedContexts() {
  return useQuery<ConfigContext[]>({
    queryKey: INTENDED_CONFIG_KEYS.contexts,
    queryFn: intendedConfigApi.contexts,
  });
}

export function useIntendedContext(id: number | null) {
  return useQuery<ConfigContext>({
    queryKey: INTENDED_CONFIG_KEYS.context(id ?? 0),
    queryFn: () => intendedConfigApi.context(id!),
    enabled: id !== null,
  });
}

/** The rows matching `filter`; `counts` ignore the filter. */
export function useIntendedHosts(filter: IntendedHostFilter) {
  return useQuery<IntendedHosts>({
    queryKey: INTENDED_CONFIG_KEYS.hosts(filter),
    queryFn: () => intendedConfigApi.hosts(filter),
    // Keep the counts and rows on screen while a filter change loads.
    placeholderData: keepPreviousData,
  });
}

/** A 404 means the host has no intended configuration. */
export function useIntendedHost(hostId: number | null) {
  return useQuery<IntendedDetail>({
    queryKey: INTENDED_CONFIG_KEYS.host(hostId ?? 0),
    queryFn: () => intendedConfigApi.host(hostId!),
    enabled: hostId !== null,
  });
}

/** What a template sees for the host; fetched only while `hostId` is set. */
export function useIntendedVariables(hostId: number | null) {
  return useQuery<HostVariables>({
    queryKey: INTENDED_CONFIG_KEYS.variables(hostId ?? 0),
    queryFn: () => intendedConfigApi.variables(hostId!),
    enabled: hostId !== null,
  });
}

export function useCreateIntendedTemplate() {
  const qc = useQueryClient();
  return useMutation<ConfigTemplate, Error, ConfigTemplateInput>({
    mutationFn: intendedConfigApi.createTemplate,
    onSuccess: () => invalidateAll(qc),
  });
}

export function useUpdateIntendedTemplate() {
  const qc = useQueryClient();
  return useMutation<ConfigTemplate, Error, { id: number; data: ConfigTemplateInput }>({
    mutationFn: ({ id, data }) => intendedConfigApi.updateTemplate(id, data),
    onSuccess: () => invalidateAll(qc),
  });
}

export function useDeleteIntendedTemplate() {
  const qc = useQueryClient();
  return useMutation<unknown, Error, number>({
    mutationFn: intendedConfigApi.deleteTemplate,
    onSuccess: () => invalidateAll(qc),
  });
}

export function useCreateIntendedContext() {
  const qc = useQueryClient();
  return useMutation<ConfigContext, Error, ConfigContextInput>({
    mutationFn: intendedConfigApi.createContext,
    onSuccess: () => invalidateAll(qc),
  });
}

export function useUpdateIntendedContext() {
  const qc = useQueryClient();
  return useMutation<ConfigContext, Error, { id: number; data: ConfigContextInput }>({
    mutationFn: ({ id, data }) => intendedConfigApi.updateContext(id, data),
    onSuccess: () => invalidateAll(qc),
  });
}

export function useDeleteIntendedContext() {
  const qc = useQueryClient();
  return useMutation<unknown, Error, number>({
    mutationFn: intendedConfigApi.deleteContext,
    onSuccess: () => invalidateAll(qc),
  });
}

/** Renders a template for a host without storing anything. */
export function usePreviewIntended() {
  return useMutation<PreviewResult, Error, PreviewRequest>({
    mutationFn: intendedConfigApi.preview,
  });
}

/** Renders and compares the chosen hosts now; an empty body means every host. */
export function useGenerateIntended() {
  const qc = useQueryClient();
  return useMutation<GenerateResult, Error, GenerateRequest>({
    mutationFn: intendedConfigApi.generate,
    onSuccess: () => invalidateAll(qc),
  });
}
