import type { ReactNode } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { RulesTab } from './RulesTab';
import { SlaTargetsTab } from './SlaTargetsTab';
import { SuppressionsTab } from './SuppressionsTab';

const mocks = vi.hoisted(() => ({
  inventoryGroupsFull: vi.fn(),
  notificationChannels: vi.fn(),
}));

const query = (data: unknown) => ({
  isError: false,
  isPending: false,
  isFetching: false,
  data,
  error: null,
  refetch: () => {},
});
const mutation = { isPending: false, mutate: () => {}, mutateAsync: async () => ({}) };

// The real Modal portals into document.body, which the node test environment
// has none of; render it in place so a mounted modal shows in the markup.
vi.mock('@/components/Modal', () => ({
  Modal: ({ isOpen, title, children }: { isOpen: boolean; title?: string; children: ReactNode }) =>
    isOpen ? <div role="dialog"><h3>{title}</h3>{children}</div> : null,
}));
vi.mock('@/components/DialogProvider-context', () => ({
  useDialogs: () => ({ confirm: async () => true, alert: async () => {} }),
}));
vi.mock('@/api/auth', () => ({ useAuthStatus: () => ({ data: { role: 'admin' } }) }));
vi.mock('@/api/inventory', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/api/inventory')>()),
  useInventoryGroupsFull: mocks.inventoryGroupsFull,
}));
vi.mock('@/api/settings', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/api/settings')>()),
  useNotificationChannels: mocks.notificationChannels,
}));
vi.mock('@/api/monitoring', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/api/monitoring')>()),
  useAlertRules: () => query([]),
  useCreateAlertRule: () => mutation,
  useUpdateAlertRule: () => mutation,
  useDeleteAlertRule: () => mutation,
  useSlaTargets: () => query([]),
  useCreateSlaTarget: () => mutation,
  useUpdateSlaTarget: () => mutation,
  useDeleteSlaTarget: () => mutation,
  useEvaluateSla: () => mutation,
  useAlertSuppressions: () => query([]),
  useCreateSuppression: () => mutation,
  useDeleteSuppression: () => mutation,
}));

describe('Monitoring form modals while closed', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.inventoryGroupsFull.mockReturnValue(query([]));
    mocks.notificationChannels.mockReturnValue(query({ channels: [] }));
  });

  it('RulesTab does not mount the rule form or start its queries', () => {
    const html = renderToStaticMarkup(<RulesTab />);
    expect(html).not.toContain('role="dialog"');
    expect(mocks.inventoryGroupsFull).not.toHaveBeenCalled();
    // Only the tab's own channel lookup runs; the form adds no second poller.
    expect(mocks.notificationChannels).toHaveBeenCalledTimes(1);
    expect(mocks.notificationChannels).toHaveBeenCalledWith();
  });

  it('SlaTargetsTab does not mount the target form or load inventory', () => {
    const html = renderToStaticMarkup(<SlaTargetsTab />);
    expect(html).not.toContain('role="dialog"');
    expect(mocks.inventoryGroupsFull).not.toHaveBeenCalled();
  });

  it('SuppressionsTab keeps the inventory query disabled until the form opens', () => {
    const html = renderToStaticMarkup(<SuppressionsTab />);
    expect(html).not.toContain('role="dialog"');
    expect(mocks.inventoryGroupsFull).toHaveBeenCalledWith(true, false);
  });
});
