import { prerender } from 'react-dom/static';
import { MemoryRouter } from 'react-router';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { Settings } from './Settings';

// Each tab module records when it is first imported, so the test can tell a
// tab that was rendered from one that was only bundled with the page.
const state = vi.hoisted(() => ({ loaded: new Set<string>(), role: 'admin' }));

vi.mock('@/api/auth', () => ({ useAuthStatus: () => ({ isLoading: false, data: { role: state.role } }) }));
vi.mock('@/api/settings', () => ({
  useAdminCapabilities: () => ({ isError: false, data: { lab_capability: true }, error: null }),
}));
vi.mock('@/components/DialogProvider-context', () => ({
  useDialogs: () => ({ confirm: async () => true, alert: async () => {} }),
}));
vi.mock('@/components/PageHelp', () => ({ PageHelp: () => null }));
vi.mock('./AppearanceTab', () => (state.loaded.add('appearance'), { AppearanceTab: () => 'appearance-tab-body' }));
vi.mock('./UsersTab', () => (state.loaded.add('users'), { UsersTab: () => 'users-tab-body' }));
vi.mock('./AuthTab', () => (state.loaded.add('auth'), { AuthTab: () => 'auth-tab-body' }));
vi.mock('./FeaturesTab', () => (state.loaded.add('features'), { FeaturesTab: () => 'features-tab-body' }));
vi.mock('./SystemTab', () => (state.loaded.add('system'), { SystemTab: () => 'system-tab-body' }));
vi.mock('./JobRetentionSection', () => (
  state.loaded.add('retention'),
  { JobRetentionSection: () => 'job-retention-body', ChangeLogRetentionSection: () => 'change-log-body' }
));

// prerender waits for every Suspense boundary, so lazy tabs are in the HTML.
async function renderAt(path: string): Promise<string> {
  const { prelude } = await prerender(
    <MemoryRouter initialEntries={[path]}>
      <Settings />
    </MemoryRouter>,
  );
  return new Response(prelude).text();
}

describe('Settings tabs', () => {
  beforeEach(() => {
    state.role = 'admin';
  });

  it('loads only the open tab, and the next one when it is opened', async () => {
    const first = await renderAt('/settings');
    expect(first).toContain('appearance-tab-body');
    // The section list names every tab without importing their code.
    expect(first).toContain('>Users<');
    expect(first).toContain('>Git Sources<');
    expect([...state.loaded]).toEqual(['appearance']);

    const users = await renderAt('/settings/users');
    expect(users).toContain('users-tab-body');
    expect(users).not.toContain('appearance-tab-body');
    expect([...state.loaded].sort()).toEqual(['appearance', 'users']);

    // The System tab renders its retention sections from a second module.
    const system = await renderAt('/settings/system');
    expect(system).toContain('system-tab-body');
    expect(system).toContain('job-retention-body');
    expect(system).toContain('change-log-body');
    expect(state.loaded.has('auth')).toBe(false);
    expect(state.loaded.has('features')).toBe(false);
  });

  it('shows a non-admin only Appearance, even on an admin tab link', async () => {
    state.role = 'user';
    const html = await renderAt('/settings/auth');
    expect(html).toContain('appearance-tab-body');
    expect(html).not.toContain('auth-tab-body');
    expect(html).not.toContain('>Users<');
    expect(state.loaded.has('auth')).toBe(false);
  });
});
