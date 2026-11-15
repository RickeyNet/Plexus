import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { FormEvent, ReactElement, ReactNode } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  type InventoryHost,
  type SnmpProfile,
  useSetHostsSnmpProfile,
  useTestHostSnmpProfile,
} from '@/api/inventory';

import { BulkSnmpProfileModal } from './BulkSnmpProfileModal';
import { HostModal } from './HostModal';

const state = vi.hoisted(() => ({
  apiRequest: vi.fn(),
  // What the last Modal and ModalActions were given.
  modalChildren: null as unknown,
  onPrimary: null as null | (() => void),
  // Replaces fields of useSetHostsSnmpProfile's result (a failed request's error).
  setHostsOverride: null as null | { error: Error },
}));

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>();
  return { ...actual, apiRequest: state.apiRequest };
});
vi.mock('@/api/inventory', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/inventory')>();
  return {
    ...actual,
    useSetHostsSnmpProfile: () => {
      const real = actual.useSetHostsSnmpProfile();
      return state.setHostsOverride ? { ...real, ...state.setHostsOverride } : real;
    },
  };
});
vi.mock('@/api/auth', () => ({
  useAuthStatus: () => ({ data: { role: 'admin', object_scope: { restricted: false, write_group_ids: [] } } }),
}));
// The real Modal portals into document.body; render it in place.
vi.mock('@/components/Modal', () => ({
  Modal: ({ title, children, footer }: { title?: string; children: ReactNode; footer?: ReactNode }) => {
    state.modalChildren = children;
    return (
      <div role="dialog">
        <h3>{title}</h3>
        {children}
        <div className="modal-footer">{footer}</div>
      </div>
    );
  },
}));
vi.mock('@/components/ModalActions', () => ({
  ModalActions: ({ primaryLabel, onPrimary }: { primaryLabel: string; onPrimary: () => void }) => {
    state.onPrimary = onPrimary;
    return <button type="button">{primaryLabel}</button>;
  },
}));

const PROFILES: SnmpProfile[] = [
  { id: 'p1', name: 'core-v3', enabled: true, version: '3' },
  { id: 'p2', name: 'branch-v2c', enabled: true, version: '2c' },
];

const HOST: InventoryHost & { group_id: number } = {
  id: 40,
  hostname: 'edge-a',
  ip_address: '192.0.2.10',
  device_type: 'cisco_ios',
  group_id: 4,
  snmp_profile_id: 'p1',
};

function render(node: ReactNode): string {
  const qc = new QueryClient();
  qc.setQueryData(['snmp-profiles'], PROFILES);
  return renderToStaticMarkup(<QueryClientProvider client={qc}>{node}</QueryClientProvider>);
}

/** The `<option>` values of the SNMP profile select, and the selected one. */
function profileOptions(html: string): { values: string[]; selected: string | undefined } {
  const select = /<select[^>]*id="[^"]*-profile"[^>]*>(.*?)<\/select>/.exec(html)?.[1] ?? '';
  return {
    values: [...select.matchAll(/<option[^>]*value="([^"]*)"/g)].map((m) => m[1]),
    selected: /<option[^>]*value="([^"]*)" selected=""/.exec(select)?.[1],
  };
}

/** Renders ``useHook`` once and returns what it gave. */
function renderHook<T>(useHook: () => T): T {
  const box: { value?: T } = {};
  function Probe() {
    box.value = useHook();
    return null;
  }
  render(<Probe />);
  return box.value as T;
}

beforeEach(() => {
  state.apiRequest.mockReset();
  state.apiRequest.mockResolvedValue({ ok: true, updated: 1 });
  state.modalChildren = null;
  state.onPrimary = null;
  state.setHostsOverride = null;
});

describe('host SNMP profile hooks', () => {
  it('set the profile of many hosts in one request', async () => {
    await renderHook(useSetHostsSnmpProfile).mutateAsync({ hostIds: [40, 41], profileId: 'p2' });
    expect(state.apiRequest).toHaveBeenCalledWith('/hosts/snmp-profile', {
      method: 'POST',
      body: { host_ids: [40, 41], snmp_profile_id: 'p2' },
    });
  });

  it('test the saved profile of one host with no body', async () => {
    await renderHook(useTestHostSnmpProfile).mutateAsync({ hostId: 40 });
    expect(state.apiRequest).toHaveBeenCalledWith('/hosts/40/snmp-profile/test', { method: 'POST' });
  });
});

describe('BulkSnmpProfileModal', () => {
  it('offers the group profile first, then each profile', () => {
    const html = render(<BulkSnmpProfileModal hostIds={[40, 41]} onClose={() => {}} />);
    expect(html).toContain('Set SNMP profile for 2 hosts');
    expect(profileOptions(html)).toEqual({ values: ['', 'p1', 'p2'], selected: '' });
    expect(html).toContain('Use the group&#x27;s profile');
    expect(html).toContain('>core-v3<');
    expect(html).toContain('>Set profile<');
    expect(html).not.toContain('role="alert"');
  });

  it('sends the selected hosts with the chosen profile', async () => {
    render(<BulkSnmpProfileModal hostIds={[40, 41]} onClose={() => {}} />);
    state.onPrimary?.();
    // The choice starts on the group profile, which clears the hosts' own.
    await vi.waitFor(() =>
      expect(state.apiRequest).toHaveBeenCalledWith('/hosts/snmp-profile', {
        method: 'POST',
        body: { host_ids: [40, 41], snmp_profile_id: '' },
      }),
    );
  });

  it('shows why the profile was not set', () => {
    state.setHostsOverride = { error: new Error('SNMP profile not found') };
    const html = render(<BulkSnmpProfileModal hostIds={[40]} onClose={() => {}} />);
    expect(html).toContain('role="alert"');
    expect(html).toContain(
      'The SNMP profile was not set: SNMP profile not found Check that the profile still exists',
    );
  });
});

describe('HostModal SNMP profile', () => {
  it('an edit starts on the host profile and offers Test SNMP', () => {
    const html = render(<HostModal host={HOST} groupId={null} groups={[]} onClose={() => {}} />);
    expect(profileOptions(html)).toEqual({ values: ['', 'p1', 'p2'], selected: 'p1' });
    expect(html).toMatch(/<label class="form-label" for="[^"]*-snmp-profile">SNMP profile<\/label>/);
    expect(html).toMatch(/<button type="button" class="btn btn-sm btn-secondary"(?![^>]*disabled)[^>]*>Test SNMP<\/button>/);
  });

  it('a new host starts on the group profile and has no test', () => {
    const html = render(<HostModal host={null} groupId={4} groups={[]} onClose={() => {}} />);
    expect(profileOptions(html).selected).toBe('');
    expect(html).not.toContain('Test SNMP');
  });

  it('an edit that leaves the profile alone does not send it', async () => {
    render(<HostModal host={HOST} groupId={null} groups={[]} onClose={() => {}} />);
    const form = state.modalChildren as ReactElement<{ onSubmit: (e: FormEvent) => Promise<void> }>;
    await form.props.onSubmit({ preventDefault: () => {} } as FormEvent);
    const [path, init] = state.apiRequest.mock.calls[0] as [string, { method: string; body: Record<string, unknown> }];
    expect(path).toBe('/hosts/40');
    expect(init.method).toBe('PUT');
    expect(init.body).not.toHaveProperty('snmp_profile_id');
  });
});
