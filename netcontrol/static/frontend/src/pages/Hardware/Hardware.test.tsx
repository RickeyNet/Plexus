import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router';
import { describe, expect, it } from 'vitest';

import { HARDWARE_KEYS, type HardwareComponent, type HardwareEvent, hardwareExportUrl } from '@/api/hardware';
import { HARDWARE_PAGE_SIZE } from '@/lib/hardware';

import { ChangesTab } from './ChangesTab';
import { ComponentsTab } from './ComponentsTab';

// Invented rows in the shape of GET /api/hardware/components and /api/hardware/events.
const COMPONENT: HardwareComponent = {
  id: 1,
  host_id: 7,
  hostname: 'core-a',
  category: 'power_supply',
  slot: 'PS1',
  name: 'Power supply 1',
  description: '',
  model: 'PWR-C1-715WAC',
  serial: 'LIT0000P1',
  hardware_rev: '',
  firmware_rev: '',
  software_rev: '',
  status: 'present',
  source: 'snmp',
  first_seen: '2026-01-01 12:00:00',
  last_seen: '2026-01-02 12:00:00',
  removed_at: null,
};

function event(id: number, over: Partial<HardwareEvent>): HardwareEvent {
  return {
    id,
    host_id: 7,
    hostname: 'core-a',
    occurred_at: '2026-01-02 12:00:00',
    event: 'replaced',
    category: 'module',
    slot: '3',
    name: 'Linecard',
    model: 'C9400-LC-48U',
    serial: 'FOC0000X0BB',
    previous_serial: 'FOC0000X0AA',
    previous_model: 'C9400-LC-48U',
    previous_slot: '',
    previous_host_id: null,
    previous_hostname: '',
    changes: {},
    detail: '',
    ...over,
  };
}

function render(node: React.ReactNode, seed: (qc: QueryClient) => void): string {
  const qc = new QueryClient();
  qc.setQueryData(['inventory-groups', false], []);
  seed(qc);
  return renderToStaticMarkup(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const FIRST_PAGE = { limit: HARDWARE_PAGE_SIZE, offset: 0 };

describe('ComponentsTab', () => {
  it('lists the components with a link to each device and the CSV export', () => {
    const html = render(<ComponentsTab />, (qc) =>
      qc.setQueryData(
        HARDWARE_KEYS.components({ search: '', category: '', status: '', group_id: null, ...FIRST_PAGE }),
        { total: 1, components: [COMPONENT] },
      ),
    );
    expect(html).toContain('href="/devices/7"');
    expect(html).toContain('LIT0000P1');
    expect(html).toContain('Power supplies');
    expect(html).toContain('href="/api/hardware/components/export"');
    expect(html).toContain('1 component');
  });
});

describe('ChangesTab', () => {
  it('asks for every change but the first reads under All changes', () => {
    const html = render(<ChangesTab />, (qc) =>
      qc.setQueryData(
        HARDWARE_KEYS.events({ search: '', event: 'replaced,installed,removed,moved,changed', category: '', ...FIRST_PAGE }),
        { total: 1, events: [event(1, {})] },
      ),
    );
    expect(html).toContain('Slot 3: FOC0000X0AA (C9400-LC-48U) replaced by FOC0000X0BB (C9400-LC-48U)');
    expect(html).toContain('1 change, newest first');
    expect(html).toContain('href="/devices/7"');
  });
});

describe('hardwareExportUrl', () => {
  it('carries the filter and leaves out empty values', () => {
    expect(hardwareExportUrl({ search: 'FOC', category: 'module', status: '', group_id: null })).toBe(
      '/api/hardware/components/export?search=FOC&category=module',
    );
  });
});
