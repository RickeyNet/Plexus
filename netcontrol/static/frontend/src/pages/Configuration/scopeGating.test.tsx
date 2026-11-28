import type { ReactNode } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { ConfigBackup, ConfigBackupPolicy, ConfigDriftEvent } from '@/api/configuration';
import type { IntendedDetail } from '@/api/intendedConfig';
import { READ_ONLY_GROUP_REASON } from '@/lib/objectScope';

import { BackupsTab } from './BackupsTab';
import { CaptureSnapshotModal } from './CaptureSnapshotModal';
import { DriftTab } from './DriftTab';
import { IntendedDetailModal } from './IntendedDetailModal';
import { SetBaselineModal } from './SetBaselineModal';
import { RAW_BACKUP_REASON, useCanDownloadBackups, writeControl } from './scopeGating';

// Group 4 (host 40) is read only, group 5 (host 50) is writable; group 6 is
// not readable at all (the server would not list it).
const state = vi.hoisted(() => ({
  scope: { restricted: true, write_group_ids: [5] } as { restricted: boolean; write_group_ids: number[] },
  features: [] as string[],
  inventoryCalls: [] as boolean[],
  detail: undefined as unknown,
}));

const query = (data: unknown) => ({ isError: false, isPending: false, isFetching: false, data, error: null, refetch: () => {} });
const mutation = { isPending: false, mutate: () => {}, mutateAsync: async () => ({}) };

const POLICIES: ConfigBackupPolicy[] = [
  { id: 1, name: 'read-only-site', group_id: 4, group_name: 'site-a', enabled: true, interval_seconds: 86400, retention_days: 30 } as ConfigBackupPolicy,
  { id: 2, name: 'writable-site', group_id: 5, group_name: 'site-b', enabled: true, interval_seconds: 86400, retention_days: 30 } as ConfigBackupPolicy,
];
const BACKUPS: ConfigBackup[] = [];
const EVENTS: ConfigDriftEvent[] = [
  { id: 11, host_id: 40, hostname: 'edge-a', ip_address: '192.0.2.10', status: 'open', diff_key: 'k1' },
  { id: 12, host_id: 50, hostname: 'edge-b', ip_address: '198.51.100.20', status: 'open', diff_key: 'k2' },
];
const GROUPS = [
  { id: 4, name: 'site-a', hosts: [{ id: 40, hostname: 'edge-a', ip_address: '192.0.2.10' }] },
  { id: 5, name: 'site-b', hosts: [{ id: 50, hostname: 'edge-b', ip_address: '198.51.100.20' }] },
];

vi.mock('@/api/auth', () => ({
  useAuthStatus: () => ({ data: { role: 'user', object_scope: state.scope, feature_access: state.features } }),
}));
vi.mock('@/api/compliance', () => ({
  useInventoryGroups: (_hosts?: boolean, enabled = true) => {
    state.inventoryCalls.push(enabled);
    return query(enabled ? GROUPS : undefined);
  },
  useCredentials: () => query([{ id: 1, name: 'lab' }]),
}));
vi.mock('@/api/settings', () => ({ useServiceCredentialsList: () => query([]) }));
vi.mock('@/api/configuration', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/api/configuration')>()),
  useConfigBackupPolicies: () => query(POLICIES),
  useConfigBackupSummary: () => query({ total_policies: 2 }),
  useConfigBackups: () => query(BACKUPS),
  useConfigDriftSummary: () => query({}),
  useConfigDriftEvents: () => query(EVENTS),
  useConfigBackupDetail: () => query(undefined),
  useConfigBackupDiff: () => query(undefined),
  useConfigDriftEvent: () => query(undefined),
  useConfigDriftEventHistory: () => query(undefined),
  useRunBackupPolicy: () => mutation,
  useDeleteBackup: () => mutation,
  useDeleteBackupPolicy: () => mutation,
  useRestoreBackup: () => mutation,
  useRevertDriftEvent: () => mutation,
  useUpdateDriftEventStatus: () => mutation,
  useBulkAcceptDriftEvents: () => mutation,
  useBulkResolveDriftEvents: () => mutation,
  useCreateBackupPolicy: () => mutation,
  useUpdateBackupPolicy: () => mutation,
  useCreateConfigBaseline: () => mutation,
  useStartCaptureGroupJob: () => mutation,
  useStartCaptureSingleJob: () => mutation,
}));
vi.mock('@/api/intendedConfig', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/api/intendedConfig')>()),
  useIntendedHost: () => query(state.detail),
  useGenerateIntended: () => mutation,
}));
vi.mock('@/api/intendedRemediation', () => ({
  useHostRemediation: () => ({ ...query(undefined), isPending: true }),
  useCreateRemediationDeployments: () => mutation,
}));
vi.mock('@/components/DialogProvider-context', () => ({
  useDialogs: () => ({ confirm: async () => true, alert: async () => {} }),
}));
// The real Modal portals into document.body; render it in place.
vi.mock('@/components/Modal', () => ({
  Modal: ({ isOpen, title, children, footer }: { isOpen?: boolean; title?: string; children: ReactNode; footer?: ReactNode }) =>
    isOpen === false ? null : (
      <div role="dialog">
        <h3>{title}</h3>
        {children}
        <div className="modal-footer">{footer}</div>
      </div>
    ),
}));

function render(node: ReactNode): string {
  return renderToStaticMarkup(<MemoryRouter>{node}</MemoryRouter>);
}

/** The opening tag of the first button whose text is ``label``. */
function button(html: string, label: string, from = 0): string {
  const m = new RegExp(`<button[^>]*>${label}</button>`).exec(html.slice(from));
  return m?.[0] ?? '';
}

beforeEach(() => {
  state.scope = { restricted: true, write_group_ids: [5] };
  state.features = [];
  state.inventoryCalls = [];
});

describe('writeControl', () => {
  it('disables with the shared reason when the group is read only', () => {
    expect(writeControl(true)).toEqual({ disabled: false });
    expect(writeControl(true, true)).toEqual({ disabled: true });
    expect(writeControl(false)).toEqual({ disabled: true, title: READ_ONLY_GROUP_REASON });
  });
});

describe('Raw backup download', () => {
  it('needs config-backups write access', () => {
    state.scope = { restricted: false, write_group_ids: [] };
    state.features = ['config-backups'];
    expect(useCanDownloadBackups()).toBe(false);
    state.features = ['config-backups', 'config-backups.write'];
    expect(useCanDownloadBackups()).toBe(true);
    expect(RAW_BACKUP_REASON).toContain('secrets');
  });
});

describe('Backups tab', () => {
  it('disables Run Now on a policy of a read-only group', () => {
    const html = render(<BackupsTab />);
    const readOnly = button(html, 'Run Now', html.indexOf('read-only-site'));
    const writable = button(html, 'Run Now', html.indexOf('writable-site'));
    expect(readOnly).toContain('disabled');
    expect(readOnly).toContain(`title="${READ_ONLY_GROUP_REASON}"`);
    expect(writable).not.toBe('');
    expect(writable).not.toContain('disabled');
  });

  it('leaves everything enabled for an unrestricted account and fetches no host map', () => {
    state.scope = { restricted: false, write_group_ids: [] };
    const html = render(<BackupsTab />);
    expect(button(html, 'Run Now', html.indexOf('read-only-site'))).not.toContain('disabled');
    expect(html).not.toContain(READ_ONLY_GROUP_REASON);
  });
});

describe('Drift tab', () => {
  it('disables Accept on an event of a read-only host and counts only writable events', () => {
    const html = render(<DriftTab onCaptureStarted={() => {}} onRevertStarted={() => {}} />);
    const readOnly = button(html, 'Accept', html.indexOf('edge-a'));
    const writable = button(html, 'Accept', html.indexOf('edge-b'));
    expect(readOnly).toContain('disabled');
    expect(readOnly).toContain(`title="${READ_ONLY_GROUP_REASON}"`);
    expect(writable).not.toContain('disabled');
    // Only one writable open event: no bulk "Accept All Open" button.
    expect(html).not.toContain('Accept All Open');
    expect(state.inventoryCalls).toContain(true);
  });

  it('offers bulk actions over every open event for an unrestricted account', () => {
    state.scope = { restricted: false, write_group_ids: [] };
    const html = render(<DriftTab onCaptureStarted={() => {}} onRevertStarted={() => {}} />);
    expect(html).toContain('Accept All Open (2)');
    expect(button(html, 'Accept', html.indexOf('edge-a'))).not.toContain('disabled');
    expect(state.inventoryCalls.every((enabled) => !enabled)).toBe(true);
  });
});

describe('Capture and baseline pickers', () => {
  it('list only writable groups and their hosts', () => {
    for (const html of [
      render(<CaptureSnapshotModal onClose={() => {}} onJobStarted={() => {}} />),
      render(<SetBaselineModal onClose={() => {}} />),
    ]) {
      expect(html).toContain('edge-b');
      expect(html).not.toContain('edge-a');
    }
    expect(render(<CaptureSnapshotModal onClose={() => {}} onJobStarted={() => {}} />)).not.toContain('site-a');
  });
});

describe('Intended detail', () => {
  const detail = (groupId: number) =>
    ({
      host_id: 40,
      hostname: 'edge-a',
      ip_address: '192.0.2.10',
      group_id: groupId,
      group_name: 'site-a',
      template_id: 1,
      template_name: 'base',
      status: 'ok',
      error: null,
      compliance: 'compliant',
      missing_count: 0,
      extra_count: 0,
      backup_id: null,
      generated_at: '',
      changed_at: '',
      compared_at: '',
      config_text: 'hostname edge-a\n',
      lines: [{ text: 'hostname edge-a', missing: false }],
      extra: [],
      backup: null,
    }) as IntendedDetail;

  it('disables Regenerate for a host of a read-only group', () => {
    state.detail = detail(4);
    const readOnly = button(render(<IntendedDetailModal hostId={40} onClose={() => {}} />), 'Regenerate');
    expect(readOnly).toContain('disabled');
    expect(readOnly).toContain(`title="${READ_ONLY_GROUP_REASON}"`);
    state.detail = detail(5);
    expect(button(render(<IntendedDetailModal hostId={40} onClose={() => {}} />), 'Regenerate')).not.toContain('disabled');
  });
});
