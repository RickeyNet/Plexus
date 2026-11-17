import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router';
import { describe, expect, it } from 'vitest';

import type { InventoryHost } from '@/api/inventory';

import { HostPanel } from './HostPanel';

const HOST: InventoryHost = {
  id: 40,
  hostname: 'edge-a',
  ip_address: '192.0.2.10',
  device_type: 'cisco_ios',
  serial_number: 'FTX0000TEST',
  software_version: '17.9.4',
  site: { id: 2, name: 'Site A' },
  custom_fields: { rack_unit: '12' },
};

const noop = () => {};

function render(auth: Record<string, unknown>, canWrite = true): string {
  const qc = new QueryClient();
  qc.setQueryData(['auth', 'status'], auth);
  return renderToStaticMarkup(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <HostPanel
          host={HOST}
          groupName="site-a"
          canWrite={canWrite}
          wide={false}
          onToggleWide={noop}
          onEdit={noop}
          onClose={noop}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('HostPanel', () => {
  it('links to the device page and to the device on the map', () => {
    const html = render({ authenticated: true, role: 'admin', feature_access: [] });
    expect(html).toContain('href="/devices/40"');
    expect(html).toContain('href="/topology?host=40"');
    expect(html).toContain('aria-label="Expand the panel to full width"');
  });

  it('shows the inventory record, custom fields included', () => {
    const html = render({ authenticated: true, role: 'admin', feature_access: [] });
    for (const text of ['edge-a', '192.0.2.10 · site-a', 'FTX0000TEST', '17.9.4', 'Site A', 'rack_unit', '12']) {
      expect(html, text).toContain(text);
    }
  });

  it('offers the config tab first and leaves out what the user may not open', () => {
    const admin = render({ authenticated: true, role: 'admin', feature_access: [] });
    expect(admin.indexOf('>Config<')).toBeGreaterThan(-1);
    expect(admin.indexOf('>Config<')).toBeLessThan(admin.indexOf('>Interfaces<'));

    const viewer = render({ authenticated: true, role: 'user', feature_access: ['inventory'] }, false);
    expect(viewer).not.toContain('href="/topology?host=40"');
    expect(viewer).not.toContain('>Config<');
    expect(viewer).toContain('>Changelog<');
    expect(viewer).toMatch(/<button[^>]*disabled=""[^>]*>Edit<\/button>/);
  });
});
