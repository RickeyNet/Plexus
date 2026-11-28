import { prerender } from 'react-dom/static';
import { MemoryRouter } from 'react-router';
import { describe, expect, it, vi } from 'vitest';

import { Monitoring } from './Monitoring';

// Each tab module records when it is first imported, so the test can tell a
// tab that was rendered from one that was only bundled with the page.
const state = vi.hoisted(() => ({
  loaded: new Set<string>(),
  auth: { role: 'admin', feature_access: [] as string[] } as Record<string, unknown>,
}));

vi.mock('@/api/auth', () => ({ useAuthStatus: () => ({ data: state.auth }) }));
vi.mock('@/components/PageHelp', () => ({ PageHelp: () => null }));
vi.mock('./DevicesTab', () => (state.loaded.add('devices'), { DevicesTab: () => 'devices-tab-body' }));
vi.mock('./AlertsTab', () => (state.loaded.add('alerts'), { AlertsTab: () => 'alerts-tab-body' }));
vi.mock('./EventsTab', () => (state.loaded.add('events'), { EventsTab: () => 'events-tab-body' }));
vi.mock('./SecurityTab', () => (state.loaded.add('security'), { SecurityTab: () => 'security-tab-body' }));
vi.mock('./SlaTab', () => (state.loaded.add('sla'), { SlaTab: () => 'sla-tab-body' }));
vi.mock('./AvailabilityTab', () => (state.loaded.add('availability'), { AvailabilityTab: () => 'availability-tab-body' }));
vi.mock('./CapacityTab', () => (state.loaded.add('capacity'), { CapacityTab: () => 'capacity-tab-body' }));
vi.mock('./ConfigureTab', () => (state.loaded.add('configure'), { ConfigureTab: () => 'configure-tab-body' }));

// prerender waits for every Suspense boundary, so lazy tabs are in the HTML.
async function renderAt(path: string): Promise<string> {
  const { prelude } = await prerender(
    <MemoryRouter initialEntries={[path]}>
      <Monitoring />
    </MemoryRouter>,
  );
  return new Response(prelude).text();
}

describe('Monitoring tabs', () => {
  it('loads only the open tab, and the next one when it is opened', async () => {
    const first = await renderAt('/monitoring');
    expect(first).toContain('devices-tab-body');
    expect(first).not.toContain('alerts-tab-body');
    // The tab bar lists every tab without importing their code.
    expect(first).toContain('>Alerts<');
    expect(first).toContain('>Configure<');
    expect([...state.loaded]).toEqual(['devices']);

    const alerts = await renderAt('/monitoring/alerts');
    expect(alerts).toContain('alerts-tab-body');
    expect(alerts).not.toContain('devices-tab-body');
    expect([...state.loaded].sort()).toEqual(['alerts', 'devices']);

    // A nested Configure deep link still resolves to the Configure tab.
    const configure = await renderAt('/monitoring/configure/rules');
    expect(configure).toContain('configure-tab-body');
    expect(state.loaded.has('events')).toBe(false);
  });

  it('keeps feature gating: a tab the user may not open is neither shown nor loaded', async () => {
    // Graph templates only: Configure is the one tab this user may open.
    state.auth = { role: 'user', feature_access: ['graph-templates'] };
    const html = await renderAt('/monitoring/sla');
    expect(html).toContain('configure-tab-body');
    expect(html).not.toContain('sla-tab-body');
    expect(html).not.toContain('>Devices<');
    expect(state.loaded.has('sla')).toBe(false);
  });
});
