import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { detailRequest } from './customData';

// Export templates: Jinja2 templates that render the objects of one type
// (hosts, IPAM prefixes and IP addresses, VLANs, circuits, sites) into a
// file. Any signed-in user lists and renders the templates of the types they
// read; admins manage them. See docs/export-templates.md.
// Failures are CustomDataError, so a 400 carries the template's error line.

export type ExportObjectType = 'host' | 'prefix' | 'ip_address' | 'vlan' | 'circuit' | 'site';

export interface ExportTemplate {
  id: number;
  name: string;
  object_type: ExportObjectType;
  description: string;
  template_text: string;
  mime_type: string;
  /** Without the leading dot; empty: the file has no extension. */
  file_extension: string;
  /** True: offered as a download; false: shown in the browser. */
  as_attachment: boolean;
  created_by: string;
  created_at: string;
  updated_by: string;
  updated_at: string;
}

export interface ExportTemplateInput {
  name: string;
  object_type: ExportObjectType;
  description: string;
  template_text: string;
  mime_type: string;
  file_extension: string;
  as_attachment: boolean;
}

export interface ExportObjectTypeInfo {
  key: ExportObjectType;
  label: string;
  feature: string;
  /** Query parameters a render accepts (besides tag= and cf.<key>= when `tags`). */
  filters: string[];
  /** The main keys of each `queryset` item. */
  fields: string[];
  tags: boolean;
  readable: boolean;
}

export interface ExportPreviewResult {
  output: string;
  error: { message: string; template: string | null; line: number | null } | null;
  /** Objects rendered, and objects of the type in all. */
  count: number;
  total: number;
}

const KEY = ['export-templates'] as const;

export function useExportTemplates(objectType?: ExportObjectType, enabled = true) {
  const qs = objectType ? `?object_type=${encodeURIComponent(objectType)}` : '';
  return useQuery<{ templates: ExportTemplate[] }>({
    queryKey: [...KEY, objectType ?? 'all'],
    queryFn: ({ signal }) => detailRequest(`/export-templates${qs}`, { signal }),
    enabled,
  });
}

export function useExportObjectTypes() {
  return useQuery<{ object_types: ExportObjectTypeInfo[] }>({
    queryKey: [...KEY, 'object-types'],
    queryFn: ({ signal }) => detailRequest('/export-templates/object-types', { signal }),
  });
}

export function useCreateExportTemplate() {
  const qc = useQueryClient();
  return useMutation<ExportTemplate, Error, ExportTemplateInput>({
    mutationFn: (data) => detailRequest<ExportTemplate>('/export-templates', { method: 'POST', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

export function useUpdateExportTemplate() {
  const qc = useQueryClient();
  return useMutation<ExportTemplate, Error, { id: number; data: ExportTemplateInput }>({
    mutationFn: ({ id, data }) => detailRequest<ExportTemplate>(`/export-templates/${id}`, { method: 'PUT', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

export function useDeleteExportTemplate() {
  const qc = useQueryClient();
  return useMutation<{ ok: boolean }, Error, number>({
    mutationFn: (id) => detailRequest(`/export-templates/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

export function usePreviewExportTemplate() {
  return useMutation<ExportPreviewResult, Error, { object_type: ExportObjectType; template_text: string; limit?: number }>({
    mutationFn: (body) => detailRequest<ExportPreviewResult>('/export-templates/preview', { method: 'POST', body }),
  });
}

/**
 * The URL that renders a template into its file (the browser downloads or
 * shows it). `params` are the list's filters (tag=, cf.<key>=, the type's
 * own); empty values are left out.
 */
export function exportTemplateRenderUrl(
  id: number,
  params?: Record<string, string | number | readonly (string | number)[] | null | undefined>,
): string {
  const qs = new URLSearchParams();
  for (const [key, value] of Object.entries(params ?? {})) {
    if (value === null || value === undefined || value === '') continue;
    for (const v of Array.isArray(value) ? value : [value]) qs.append(key, String(v));
  }
  const query = qs.toString();
  return `/api/export-templates/${id}/render${query ? `?${query}` : ''}`;
}
