import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router';
import { describe, expect, it } from 'vitest';

import { HARDWARE_KEYS, type HardwareComponent, type HardwareEvent, type HostHardware } from '@/api/hardware';

import { HardwareTab } from './HardwareTab';

// Invented components and events in the shape GET /api/hosts/{id}/hardware returns.
function component(over: Partial<HardwareComponent>): HardwareComponent {
  return {
    id: 1,
    host_id: 7,
    hostname: 'core-a',
    category: 'module',
    slot: '1',
    name: 'Linecard',
    description: '',
    model: 'C9400-LC-48U',
    serial: 'FOC0000X0AA',
    hardware_rev: 'V01',
    firmware_rev: '17.9.4',
    software_rev: '',
    status: 'present',
    source: 'snmp',
    first_seen: '2026-01-01 12:00:00',
    last_seen: '2026-01-02 12:00:00',
    removed_at: null,
    ...over,
  };
}

const HARDWARE: HostHardware = {
  host_id: 7,
  collected_at: '2026-01-02 12:00:00',
  source: 'snmp',
  state: 'ok',
  message: '',
  components: [
    component({ id: 1, category: 'transceiver', slot: 'Te1/0/1', name: 'SFP-10G-SR', serial: 'AGM0000A1' }),
    component({ id: 2, category: 'chassis', slot: '', name: 'Chassis', model: 'C9407R', serial: 'FXS0000C1' }),
    component({ id: 3, slot: '3', serial: 'FOC0000X0BB', status: 'missing' }),
    component({ id: 4, category: 'power_supply', slot: 'PS1', serial: 'LIT0000P1', status: 'removed', removed_at: '2026-01-02 12:00:00' }),
  ],
};

const EVENTS: HardwareEvent[] = [
  {
    id: 11,
    host_id: 7,
    hostname: 'core-a',
    occurred_at: '2026-01-02 12:00:00',
    event: 'installed',
    category: 'module',
    slot: '4',
    name: 'Linecard',
    model: 'C9400-LC-48U',
    serial: 'FOC0000X0CC',
    previous_serial: '',
    previous_model: '',
    previous_slot: '',
    previous_host_id: 9,
    previous_hostname: 'core-b',
    changes: {},
    detail: '',
  },
];

function render(auth: Record<string, unknown>, hardware: HostHardware = HARDWARE, total = 1): string {
  const qc = new QueryClient();
  qc.setQueryData(['auth', 'status'], auth);
  qc.setQueryData(HARDWARE_KEYS.host(7), hardware);
  qc.setQueryData(HARDWARE_KEYS.hostEvents(7), { pages: [{ total, events: EVENTS }], pageParams: [0] });
  return renderToStaticMarkup(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <HardwareTab hostId={7} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const ADMIN = { authenticated: true, role: 'admin', feature_access: [] };
const VIEWER = { authenticated: true, role: 'user', feature_access: ['inventory'] };

describe('HardwareTab', () => {
  it('groups the components by category, chassis first, and hides removed ones', () => {
    const html = render(ADMIN);
    const order = ['>Chassis <', '>Modules <', '>Transceivers <'].map((t) => html.indexOf(t));
    expect(order.every((i) => i > -1)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
    expect(html).not.toContain('LIT0000P1');
    expect(html).toContain('Show removed (1)');
  });

  it('marks a missing component and explains it', () => {
    const html = render(ADMIN);
    expect(html).toContain('FOC0000X0BB');
    expect(html).toMatch(/badge-warning[^>]*>Missing</);
    expect(html).toContain('1 component was not in the last read');
  });

  it('says when and how the hardware was read, and offers a refresh to writers only', () => {
    const admin = render(ADMIN);
    expect(admin).toContain('over SNMP');
    expect(admin).toContain('Refresh hardware');
    expect(render(VIEWER)).not.toContain('Refresh hardware');
  });

  it('shows why the hardware was not read', () => {
    const html = render(ADMIN, {
      ...HARDWARE,
      collected_at: null,
      source: '',
      state: 'not_read',
      message: 'The device does not answer the entity table over SNMP.',
      components: [],
    });
    expect(html).toContain('Hardware not read yet.');
    expect(html).toContain('The device does not answer the entity table over SNMP.');
    expect(html).toContain('No hardware components recorded for this device.');
  });

  it('lists the history with a link to the host a part came from, and pages it', () => {
    const html = render(ADMIN, HARDWARE, 250);
    expect(html).toContain('Slot 4: FOC0000X0CC (C9400-LC-48U) installed');
    expect(html).toContain('href="/devices/9"');
    expect(html).toContain('1 of 250 changes');
    expect(html).toContain('Load more');
    expect(render(ADMIN, HARDWARE, 1)).not.toContain('Load more');
  });
});
