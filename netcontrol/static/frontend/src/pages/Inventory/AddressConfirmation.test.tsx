import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router';
import { describe, expect, it } from 'vitest';

import { addressAwaitingConfirmation, awaitingHostIds, type InventoryHost } from '@/api/inventory';
import { DialogContext } from '@/components/DialogProvider-context';

import { HostPanel } from './HostPanel';

const CONFIRMED: InventoryHost = { id: 1, hostname: 'core-a', ip_address: '192.0.2.1', address_confirmed: 1 };
const AWAITING: InventoryHost = { id: 2, hostname: 'edge-b', ip_address: '203.0.113.10', address_confirmed: 0 };

const noop = () => {};
const dialogs = { confirm: async () => false, alert: async () => {} };

function render(host: InventoryHost, role: string): string {
  const qc = new QueryClient();
  qc.setQueryData(['auth', 'status'], { authenticated: true, role, feature_access: [] });
  return renderToStaticMarkup(
    <QueryClientProvider client={qc}>
      <DialogContext.Provider value={dialogs}>
        <MemoryRouter>
          <HostPanel
            host={host}
            groupName="site-a"
            canWrite
            wide={false}
            onToggleWide={noop}
            onEdit={noop}
            onClose={noop}
          />
        </MemoryRouter>
      </DialogContext.Provider>
    </QueryClientProvider>,
  );
}

describe('host address confirmation', () => {
  it('tells an unconfirmed address from a confirmed one (an older server sends no flag)', () => {
    expect(addressAwaitingConfirmation(AWAITING)).toBe(true);
    expect(addressAwaitingConfirmation({ address_confirmed: false })).toBe(true);
    expect(addressAwaitingConfirmation(CONFIRMED)).toBe(false);
    expect(addressAwaitingConfirmation({})).toBe(false);
    expect(awaitingHostIds([CONFIRMED, AWAITING])).toEqual([2]);
  });

  it('marks an unconfirmed host and offers an admin the confirm action', () => {
    const html = render(AWAITING, 'admin');
    expect(html).toContain('Awaiting admin confirmation');
    expect(html).toContain('Confirm address');
  });

  it('marks an unconfirmed host for a non-admin, without the confirm action', () => {
    const html = render(AWAITING, 'user');
    expect(html).toContain('Awaiting admin confirmation');
    expect(html).not.toContain('Confirm address');
  });

  it('shows neither for a confirmed host', () => {
    const html = render(CONFIRMED, 'admin');
    expect(html).not.toContain('Awaiting admin confirmation');
    expect(html).not.toContain('Confirm address');
  });
});
