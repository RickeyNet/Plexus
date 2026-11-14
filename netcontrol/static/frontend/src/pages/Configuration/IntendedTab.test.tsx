import type { ReactNode } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { ConfigContext, ConfigTemplate, IntendedCounts, IntendedDetail, IntendedRow } from '@/api/intendedConfig';

import { ContextModal } from './ContextModal';
import { IntendedContextsView } from './IntendedContextsView';
import { IntendedDetailModal } from './IntendedDetailModal';
import { IntendedDevicesView } from './IntendedDevicesView';
import { IntendedTab } from './IntendedTab';
import { IntendedTemplatesView } from './IntendedTemplatesView';
import { PreviewResultView, VariablesView } from './TemplatePreviewPane';
import { TemplateModal } from './TemplateModal';

const state = vi.hoisted(() => ({
  hosts: {} as Record<string, unknown>,
  host: {} as Record<string, unknown>,
  templates: {} as Record<string, unknown>,
  contexts: {} as Record<string, unknown>,
  role: 'admin',
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

vi.mock('@/api/intendedConfig', () => ({
  useIntendedHosts: () => state.hosts,
  useIntendedHost: () => state.host,
  useIntendedTemplates: () => state.templates,
  useIntendedContexts: () => state.contexts,
  useIntendedVariables: () => query({ isPending: true }),
  useGenerateIntended: () => mutation,
  usePreviewIntended: () => mutation,
  useCreateIntendedTemplate: () => mutation,
  useUpdateIntendedTemplate: () => mutation,
  useDeleteIntendedTemplate: () => mutation,
  useCreateIntendedContext: () => mutation,
  useUpdateIntendedContext: () => mutation,
  useDeleteIntendedContext: () => mutation,
}));
vi.mock('@/api/compliance', () => ({
  useInventoryGroups: () =>
    query({
      data: [
        { id: 4, name: 'Branches', hosts: [{ id: 9, hostname: 'edge-1', ip_address: '192.0.2.1' }] },
        { id: 5, name: 'Core', hosts: [] },
      ],
    }),
}));
vi.mock('@/api/deviceModel', () => ({ useDeviceRoles: () => query({ data: [{ id: 2, name: 'core' }] }) }));
vi.mock('@/api/floorPlan', () => ({ useGeoSites: () => query({ data: [{ id: 3, name: 'Branch 1' }] }) }));
vi.mock('@/api/auth', () => ({ useAuthStatus: () => ({ data: { role: state.role } }) }));
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

const COUNTS: IntendedCounts = { hosts: 5, generated: 2, errors: 1, compliant: 0, non_compliant: 1, unknown: 1, no_template: 3 };

const ROW: IntendedRow = {
  host_id: 9,
  hostname: 'edge-1',
  ip_address: '192.0.2.1',
  group_id: 4,
  group_name: 'Branches',
  template_id: 1,
  template_name: 'branch-edge',
  status: 'ok',
  error: null,
  compliance: 'non_compliant',
  missing_count: 2,
  extra_count: 1,
  backup_id: 40,
  generated_at: '2026-11-14 08:00:00',
  changed_at: '2026-11-14 08:00:00',
  compared_at: '2026-11-14 08:00:00',
};

const ERROR_ROW: IntendedRow = {
  ...ROW,
  host_id: 10,
  hostname: 'edge-2',
  ip_address: '192.0.2.2',
  status: 'error',
  error: "Line 3: 'context' has no attribute 'ntp'",
  compliance: 'unknown',
  missing_count: 0,
  extra_count: 0,
};

const TEMPLATE: ConfigTemplate = {
  id: 1,
  name: 'branch-edge',
  kind: 'device',
  device_type: 'cisco_ios',
  role_id: 2,
  site_id: 77,
  group_id: null,
  template_text: 'hostname {{ host.name }}\n',
  description: 'Branch routers',
  enabled: true,
  created_at: '2026-11-01 00:00:00',
  updated_at: '2026-11-02 00:00:00',
  updated_by: 'admin',
  host_count: 2,
};

const CONTEXT: ConfigContext = {
  id: 3,
  name: 'ntp',
  weight: 1000,
  data: { ntp_servers: ['192.0.2.10'] },
  description: '',
  enabled: false,
  device_type: '',
  role_id: null,
  site_id: null,
  group_id: null,
  host_id: 9,
  created_at: '2026-11-01 00:00:00',
  updated_at: '2026-11-02 00:00:00',
  updated_by: 'admin',
};

const devices = () => renderToStaticMarkup(<IntendedDevicesView isAdmin={state.role === 'admin'} onShowTemplates={() => {}} />);

describe('IntendedTab', () => {
  it('opens on the Devices view behind a segmented control', () => {
    state.hosts = query({ isPending: true });
    const html = renderToStaticMarkup(<IntendedTab />);
    expect(html).toContain('role="radiogroup"');
    for (const label of ['Devices', 'Templates', 'Contexts']) expect(html).toContain(`>${label}</button>`);
    expect(html).toContain('Loading intended configurations…');
  });
});

describe('IntendedDevicesView', () => {
  beforeEach(() => {
    state.role = 'admin';
  });

  it('shows the failure with a retry', () => {
    state.hosts = query({ isError: true, error: new Error('500 Internal Server Error') });
    const html = devices();
    expect(html).toContain('Failed to load intended configurations');
    expect(html).toContain('Retry');
  });

  it('tells an admin to add a template when nothing is generated', () => {
    state.hosts = query({ data: { rows: [], counts: { ...COUNTS, generated: 0 } } });
    const admin = devices();
    expect(admin).toContain('No intended configurations yet.');
    expect(admin).toContain('Add a device template on the Templates view');
    expect(admin).toContain('Open Templates');
    state.role = 'user';
    const user = devices();
    expect(user).toContain('An administrator adds device templates');
    expect(user).not.toContain('Open Templates');
  });

  it('shows the counts, the filters and Generate all', () => {
    state.hosts = query({ data: { rows: [ROW], counts: COUNTS } });
    const html = devices();
    for (const text of ['Hosts', 'Non-compliant', 'No template', 'Generate all', 'aria-label="Filter by group"', 'aria-label="Filter by compliance"']) {
      expect(html).toContain(text);
    }
    expect(html).toContain('<option value="4">Branches</option>');
    expect(html).toContain('<option value="non_compliant">Non-compliant</option>');
    expect(html).toMatch(/<div class="stat-value">3<\/div><div class="stat-label">No template/);
  });

  it('lists the rows with status and compliance badges and the error of a failed render', () => {
    state.hosts = query({ data: { rows: [ROW, ERROR_ROW], counts: COUNTS } });
    const html = devices();
    for (const text of ['edge-1', '192.0.2.1', 'Branches', 'branch-edge', 'non compliant', 'edge-2', "Line 3: &#x27;context&#x27; has no attribute &#x27;ntp&#x27;"]) {
      expect(html).toContain(text);
    }
    expect(html).toMatch(/badge-danger[^>]*>error</);
    expect(html).toMatch(/<tr[^>]*tabindex="0"/);
  });
});

describe('IntendedDetailModal', () => {
  const DETAIL: IntendedDetail = {
    ...ROW,
    config_text: 'hostname edge-1\nntp server 192.0.2.10\n',
    lines: [
      { text: 'hostname edge-1', missing: false },
      { text: 'ntp server 192.0.2.10', missing: true },
    ],
    extra: [{ path: ['interface Gi0/1'], text: ' shutdown' }],
    backup: { id: 40, captured_at: '2026-11-14 07:00:00' },
  };

  it('marks missing lines with a marker and a label, and lists extras under their parent', () => {
    state.host = query({ data: DETAIL });
    const html = renderToStaticMarkup(<IntendedDetailModal hostId={9} onClose={() => {}} />);
    expect(html).toContain('Intended configuration: edge-1');
    expect(html).toContain(
      '<span class="diff-removed"><span aria-hidden="true">- </span><span class="sr-only">Missing: </span>ntp server 192.0.2.10',
    );
    expect(html).not.toContain('Missing: </span>hostname edge-1');
    expect(html).toContain('Extra on device (1)');
    expect(html).toContain('interface Gi0/1');
    expect(html).toContain('shutdown');
    expect(html).toContain('backup 40');
    for (const label of ['Copy', 'Regenerate', 'Close']) expect(html).toContain(label);
  });

  it('says when there was no backup to compare with, and shows a render error', () => {
    state.host = query({ data: { ...DETAIL, backup: null, status: 'error', error: 'Line 1: boom', lines: [], extra: [], compliance: 'unknown' } });
    const html = renderToStaticMarkup(<IntendedDetailModal hostId={9} onClose={() => {}} />);
    expect(html).toContain('No backup to compare with.');
    expect(html).toContain('The template did not render');
    expect(html).toContain('Line 1: boom');
    expect(html).toContain('No extra lines on the device.');
  });
});

describe('IntendedTemplatesView', () => {
  beforeEach(() => {
    state.role = 'admin';
  });

  it('gives admins Add, Edit and Delete and others none', () => {
    state.templates = query({ data: [TEMPLATE, { ...TEMPLATE, id: 2, name: 'ntp-snippet', kind: 'snippet', enabled: false, host_count: 0 }] });
    const admin = renderToStaticMarkup(<IntendedTemplatesView isAdmin />);
    for (const text of ['Add template', 'aria-label="Edit template branch-edge"', 'aria-label="Delete template ntp-snippet"']) {
      expect(admin).toContain(text);
    }
    expect(admin).toContain('Driver Cisco IOS · Role core · Site (deleted)');
    expect(admin).toContain('Included by other templates');
    expect(admin).toContain('Disabled');
    const user = renderToStaticMarkup(<IntendedTemplatesView isAdmin={false} />);
    expect(user).toContain('branch-edge');
    expect(user).not.toContain('Add template');
    expect(user).not.toContain('Edit template');
    expect(user).not.toContain('Delete template');
  });

  it('shows the empty state with Add only for admins', () => {
    state.templates = query({ data: [] });
    expect(renderToStaticMarkup(<IntendedTemplatesView isAdmin />)).toContain('Add template');
    const user = renderToStaticMarkup(<IntendedTemplatesView isAdmin={false} />);
    expect(user).toContain('No templates yet.');
    expect(user).not.toContain('Add template');
  });
});

describe('TemplateModal', () => {
  it('edits with scope pickers, a monospace editor and the preview pane', () => {
    const html = renderToStaticMarkup(<TemplateModal template={TEMPLATE} onClose={() => {}} />);
    expect(html).toContain('Edit template branch-edge');
    expect(html).toMatch(/<textarea[^>]*class="form-textarea drift-baseline-textarea"/);
    expect(html).toContain('<option value="77" selected="">(deleted)</option>');
    expect(html).toContain('<option value="cisco_ios" selected="">Cisco IOS</option>');
    expect(html).toContain('<option value="9">edge-1 (192.0.2.1)</option>');
    for (const text of ['Preview', 'Variables', 'Save template']) expect(html).toContain(text);
  });

  it('hides the scope of a snippet', () => {
    const html = renderToStaticMarkup(<TemplateModal template={{ ...TEMPLATE, kind: 'snippet' }} onClose={() => {}} />);
    expect(html).not.toContain('Applies to');
  });

  it('is read only for non-admins: no preview and no save', () => {
    const html = renderToStaticMarkup(<TemplateModal template={TEMPLATE} readOnly onClose={() => {}} />);
    expect(html).toMatch(/<textarea[^>]*readOnly=""/);
    expect(html).not.toContain('Save template');
    expect(html).not.toContain('>Preview<');
  });
});

describe('preview results', () => {
  it('shows the rendered text', () => {
    const html = renderToStaticMarkup(<PreviewResultView result={{ template_name: 'branch-edge', config_text: 'hostname edge-1\n', error: null }} />);
    expect(html).toContain('Rendered from branch-edge');
    expect(html).toContain('hostname edge-1');
  });

  it('shows the error with its line', () => {
    const html = renderToStaticMarkup(
      <PreviewResultView result={{ template_name: 'branch-edge', config_text: '', error: { message: 'boom', template: 'branch-edge', line: 4 } }} />,
    );
    expect(html).toContain('The template did not render');
    expect(html).toContain('Line 4: boom');
  });

  it('shows the variables as JSON and the merged contexts', () => {
    const html = renderToStaticMarkup(
      <VariablesView data={{ variables: { host: { name: 'edge-1' } }, contexts: [{ id: 3, name: 'ntp', weight: 1000 }] }} />,
    );
    expect(html).toContain('Contexts merged, in order: ntp (1000).');
    expect(html).toContain('&quot;name&quot;: &quot;edge-1&quot;');
  });
});

describe('IntendedContextsView and ContextModal', () => {
  it('lists contexts with weight and host scope', () => {
    state.contexts = query({ data: [CONTEXT] });
    const html = renderToStaticMarkup(<IntendedContextsView isAdmin />);
    for (const text of ['ntp', '1,000', 'Host edge-1', 'Disabled', 'Add context', 'aria-label="Delete context ntp"']) {
      expect(html).toContain(text);
    }
    expect(renderToStaticMarkup(<IntendedContextsView isAdmin={false} />)).not.toContain('Add context');
  });

  it('edits the weight, the scope with one host, and the JSON data', () => {
    const html = renderToStaticMarkup(<ContextModal context={CONTEXT} onClose={() => {}} />);
    expect(html).toContain('Edit context ntp');
    expect(html).toContain('value="1000"');
    expect(html).toContain('<option value="9" selected="">edge-1</option>');
    expect(html).toContain('&quot;ntp_servers&quot;');
    expect(html).toContain('Save context');
  });
});
