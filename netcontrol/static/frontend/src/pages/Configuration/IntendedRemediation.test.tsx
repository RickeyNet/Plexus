import type { ReactNode } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { HostRemediation, IgnoreRule } from '@/api/intendedRemediation';
import { deploymentIdFromSearch } from '@/pages/Deployments/helpers';

import { IntendedIgnoresView } from './IntendedIgnoresView';
import { commandsText, deploymentHref, remediationSummary } from './intendedHelpers';
import { DeploymentResult, RemediationSection } from './IntendedRemediation';

const state = vi.hoisted(() => ({
  remediation: {} as Record<string, unknown>,
  ignores: {} as Record<string, unknown>,
  role: 'admin',
  features: [] as string[],
  writeGroups: [] as number[] | null,
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

vi.mock('@/api/intendedRemediation', () => ({
  useHostRemediation: () => state.remediation,
  useCreateRemediationDeployments: () => mutation,
  useRemediationIgnores: () => state.ignores,
  useCreateRemediationIgnore: () => mutation,
  useUpdateRemediationIgnore: () => mutation,
  useDeleteRemediationIgnore: () => mutation,
}));
vi.mock('@/api/compliance', () => ({ useCredentials: () => query({ data: [{ id: 5, name: 'lab-operator' }] }) }));
vi.mock('@/api/auth', () => ({
  useAuthStatus: () => ({
    data: {
      role: state.role,
      feature_access: state.features,
      feature_visibility_hidden: [],
      object_scope: state.writeGroups ? { restricted: true, write_group_ids: state.writeGroups } : { restricted: false, write_group_ids: [] },
    },
  }),
}));
vi.mock('@/components/DialogProvider-context', () => ({
  useDialogs: () => ({ confirm: async () => true, alert: async () => {} }),
}));

const OK: HostRemediation = {
  host_id: 9,
  hostname: 'edge-1',
  ip_address: '192.0.2.1',
  device_type: 'cisco_ios',
  group_id: 4,
  template_name: 'branch-edge',
  backup: { id: 40, captured_at: '2026-11-14 08:00:00' },
  state: 'ok',
  reason: '',
  supported: true,
  platform: 'Cisco IOS',
  commands: ['interface Gi0/1', ' no description old-link', ' description uplink'],
  added: 1,
  removed: 1,
  ignored: 2,
  notes: [],
};

const section = () =>
  renderToStaticMarkup(
    <MemoryRouter>
      <RemediationSection hostId={9} groupId={4} />
    </MemoryRouter>,
  );

const wrap = (node: ReactNode) => renderToStaticMarkup(<MemoryRouter>{node}</MemoryRouter>);

describe('remediation helpers', () => {
  it('summarises, joins and links', () => {
    expect(remediationSummary(OK)).toBe('3 commands: 1 added, 1 removed; 2 lines ignored by rules');
    expect(remediationSummary({ ...OK, commands: ['x'], ignored: 0 })).toBe('1 command: 1 added, 1 removed');
    expect(commandsText(OK.commands)).toBe('interface Gi0/1\n no description old-link\n description uplink\n');
    expect(commandsText([])).toBe('');
    expect(deploymentHref(12)).toBe('/change-management/deployments?deployment=12');
  });

  it('reads the deployment a link opens', () => {
    expect(deploymentIdFromSearch('deployment=12')).toBe(12);
    expect(deploymentIdFromSearch('?deployment=12&x=1')).toBe(12);
    for (const bad of ['', 'deployment=', 'deployment=abc', 'deployment=0', 'deployment=-3', 'deployment=1.5']) {
      expect(deploymentIdFromSearch(bad)).toBeNull();
    }
  });
});

describe('RemediationSection', () => {
  beforeEach(() => {
    state.role = 'admin';
    state.features = [];
    state.writeGroups = null;
  });

  it('shows the commands with Copy and Create deployment for an admin', () => {
    state.remediation = query({ data: OK });
    const html = section();
    expect(html).toContain('aria-label="Remediation commands"');
    expect(html).toContain(' no description old-link');
    expect(html).toContain('3 commands: 1 added, 1 removed');
    expect(html).toContain('Copy commands');
    expect(html).toContain('Create deployment');
    expect(html).toContain('<option value="5">lab-operator</option>');
    // No credential chosen yet: the button waits for one.
    expect(html).toMatch(/<button[^>]*disabled=""[^>]*>Create deployment<\/button>/);
  });

  it('hides Create deployment without the Deployments feature and disables it on a read-only group', () => {
    state.remediation = query({ data: OK });
    state.role = 'user';
    state.features = ['config-drift'];
    expect(section()).not.toContain('Create deployment');
    state.features = ['config-drift', 'deployments'];
    state.writeGroups = [7];
    const html = section();
    expect(html).toContain('Create deployment');
    expect(html).toMatch(/title="[^"]*[Rr]ead-only[^"]*"/);
  });

  it('explains an unsupported driver, a missing comparison and a compliant device', () => {
    state.remediation = query({ data: { ...OK, state: 'unsupported', commands: [], reason: "Remediation is not supported for driver 'juniper_junos'." } });
    expect(section()).toContain('Not supported');
    state.remediation = query({ data: { ...OK, state: 'unavailable', commands: [], reason: 'No configuration backup to compare with.' } });
    expect(section()).toContain('No configuration backup to compare with.');
    state.remediation = query({ data: { ...OK, commands: [], added: 0, removed: 0 } });
    const html = section();
    expect(html).toContain('Nothing to push');
    expect(html).not.toContain('Create deployment');
  });

  it('shows notes, loading and errors', () => {
    state.remediation = query({ data: { ...OK, notes: ['Banner lines differ; banners are not remediated, change them by hand.'] } });
    expect(section()).toContain('Banner lines differ');
    state.remediation = query({ isPending: true });
    expect(section()).toContain('Working out the remediation…');
    state.remediation = query({ isError: true, error: new Error('500 Internal Server Error') });
    expect(section()).toContain('Retry');
  });
});

describe('DeploymentResult', () => {
  it('links to the planned deployment and says when it needs approval', () => {
    const html = wrap(
      <DeploymentResult
        result={{
          deployments: [{ id: 12, host_id: 9, hostname: 'edge-1', status: 'planning', requires_approval: true, approval_status: 'pending', commands: 3 }],
          skipped: [],
        }}
      />,
    );
    expect(html).toContain('href="/change-management/deployments?deployment=12"');
    expect(html).toContain('needs approval');
  });

  it('gives the reason when nothing was created', () => {
    const html = wrap(<DeploymentResult result={{ deployments: [], skipped: [{ host_id: 9, hostname: 'edge-1', reason: 'The device already matches its intended configuration.' }] }} />);
    expect(html).toContain('No deployment was created: The device already matches');
  });
});

describe('IntendedIgnoresView', () => {
  const RULE: IgnoreRule = {
    id: 1,
    kind: 'regex',
    pattern: '^ntp clock-period',
    device_type: 'cisco_ios',
    description: 'Set by the device',
    enabled: true,
    created_at: '2026-11-01 00:00:00',
    updated_at: '2026-11-01 00:00:00',
    updated_by: 'admin',
  };

  it('lists the rules with their match kind and actions, and the add form', () => {
    state.ignores = query({ data: [RULE] });
    const html = renderToStaticMarkup(<IntendedIgnoresView />);
    for (const text of ['^ntp clock-period', 'Set by the device', 'Regular expression', 'cisco_ios', 'Disable', 'Delete', 'Add rule', 'Pattern']) {
      expect(html).toContain(text);
    }
  });

  it('explains the view when there are no rules', () => {
    state.ignores = query({ data: [] });
    expect(renderToStaticMarkup(<IntendedIgnoresView />)).toContain('No ignore rules yet.');
  });
});
