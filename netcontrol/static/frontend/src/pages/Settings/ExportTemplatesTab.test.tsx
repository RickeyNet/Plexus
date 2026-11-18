import type { ReactNode } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { ExportObjectTypeInfo, ExportTemplate } from '@/api/exportTemplates';
import { exportTemplateRenderUrl } from '@/api/exportTemplates';
import { ExportTemplatesMenu } from '@/components/ExportTemplatesMenu';

import { ExportPreviewView, ExportTemplateModal } from './ExportTemplateModal';
import { ExportTemplatesTab } from './ExportTemplatesTab';

const state = vi.hoisted(() => ({
  templates: {} as Record<string, unknown>,
  types: {} as Record<string, unknown>,
}));

const query = (over: Record<string, unknown>) => ({
  isError: false,
  isPending: false,
  isFetching: false,
  data: undefined,
  error: null,
  refetch: () => {},
  ...over,
});
const mutation = { isPending: false, isError: false, data: undefined, mutate: () => {}, mutateAsync: async () => ({}) };

vi.mock('@/api/exportTemplates', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/exportTemplates')>();
  return {
    ...actual,
    useExportTemplates: () => state.templates,
    useExportObjectTypes: () => state.types,
    useCreateExportTemplate: () => mutation,
    useUpdateExportTemplate: () => mutation,
    useDeleteExportTemplate: () => mutation,
    usePreviewExportTemplate: () => mutation,
  };
});
vi.mock('@/components/DialogProvider-context', () => ({
  useDialogs: () => ({ confirm: async () => true, alert: async () => {} }),
}));
// The real Modal portals into document.body, which the node test environment
// has none of; render its title, body and footer in place instead.
vi.mock('@/components/Modal', () => ({
  Modal: ({ title, children, footer }: { title?: string; children: ReactNode; footer?: ReactNode }) => (
    <div role="dialog">
      <h3>{title}</h3>
      {children}
      <div className="modal-footer">{footer}</div>
    </div>
  ),
}));

const TYPES: ExportObjectTypeInfo[] = [
  { key: 'host', label: 'Hosts', feature: 'inventory', filters: ['group_id'], fields: ['hostname', 'ip_address'], tags: true, readable: true },
  { key: 'vlan', label: 'VLANs', feature: 'ipam', filters: ['vid'], fields: ['vid', 'name'], tags: true, readable: true },
];

const TEMPLATE: ExportTemplate = {
  id: 3,
  name: 'hosts csv',
  object_type: 'host',
  description: 'Every host as CSV',
  template_text: '{% for h in queryset %}{{ h.hostname }}{% endfor %}',
  mime_type: 'text/csv',
  file_extension: 'csv',
  as_attachment: true,
  created_by: 'admin',
  created_at: '2026-11-17 08:00:00',
  updated_by: 'admin',
  updated_at: '2026-11-17 08:00:00',
};

beforeEach(() => {
  state.templates = query({ data: { templates: [TEMPLATE] } });
  state.types = query({ data: { object_types: TYPES } });
});

describe('exportTemplateRenderUrl', () => {
  it('keeps only the filters that are set, repeating list values', () => {
    expect(exportTemplateRenderUrl(3)).toBe('/api/export-templates/3/render');
    expect(exportTemplateRenderUrl(3, { group_id: 4, status: '', q: undefined, tag: ['core', 'edge'] })).toBe(
      '/api/export-templates/3/render?group_id=4&tag=core&tag=edge',
    );
  });
});

describe('ExportTemplatesTab', () => {
  it('lists the templates with their type, file and actions', () => {
    const html = renderToStaticMarkup(<ExportTemplatesTab />);
    for (const text of ['hosts csv', 'Every host as CSV', 'Hosts', 'text/csv', '.csv', 'Add export template', 'Edit']) {
      expect(html).toContain(text);
    }
    expect(html).toContain('href="/api/export-templates/3/render"');
  });

  it('shows the empty state with the add action', () => {
    state.templates = query({ data: { templates: [] } });
    const html = renderToStaticMarkup(<ExportTemplatesTab />);
    expect(html).toContain('No export templates yet.');
    expect(html).toContain('Add export template');
  });
});

describe('ExportTemplateModal', () => {
  it('edits with a monospace editor, the type fields and the preview pane', () => {
    const html = renderToStaticMarkup(<ExportTemplateModal template={TEMPLATE} objectTypes={TYPES} onClose={() => {}} />);
    expect(html).toContain('Edit export template hosts csv');
    expect(html).toMatch(/<textarea[^>]*class="form-textarea drift-baseline-textarea"/);
    expect(html).toContain('<option value="host" selected="">Hosts</option>');
    expect(html).toContain('hostname, ip_address');
    for (const text of ['Preview', 'Save template', 'MIME type', 'File extension']) expect(html).toContain(text);
  });

  it('shows a rendered preview or its error line', () => {
    const ok = renderToStaticMarkup(<ExportPreviewView result={{ output: 'a,b\n', error: null, count: 2, total: 9 }} />);
    expect(ok).toContain('first 2 of 9 objects');
    expect(ok).toContain('a,b');
    const bad = renderToStaticMarkup(
      <ExportPreviewView result={{ output: '', error: { message: 'boom', template: 'export', line: 4 }, count: 0, total: 0 }} />,
    );
    expect(bad).toContain('Line 4: boom');
  });
});

describe('ExportTemplatesMenu', () => {
  it('offers nothing without templates', () => {
    state.templates = query({ data: { templates: [] } });
    expect(renderToStaticMarkup(<ExportTemplatesMenu objectType="host" />)).toBe('');
  });

  it('renders the Export trigger when the type has templates', () => {
    expect(renderToStaticMarkup(<ExportTemplatesMenu objectType="host" />)).toContain('Export ▾');
  });
});
