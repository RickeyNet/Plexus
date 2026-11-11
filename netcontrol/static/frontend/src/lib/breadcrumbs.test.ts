import { describe, expect, it } from 'vitest';

import { breadcrumbTrail } from './breadcrumbs';

describe('breadcrumbTrail', () => {
  it('is empty on the overview dashboard and on unknown paths', () => {
    expect(breadcrumbTrail('/')).toEqual([]);
    expect(breadcrumbTrail('/nope')).toEqual([]);
  });

  it('gives a single unlinked crumb for an untabbed page', () => {
    expect(breadcrumbTrail('/inventory')).toEqual([{ label: 'Inventory' }]);
  });

  it('links a tab back to its page', () => {
    expect(breadcrumbTrail('/monitoring/alerts')).toEqual([
      { label: 'Monitoring', to: '/monitoring' },
      { label: 'Alerts' },
    ]);
  });

  it('does not link the page crumb to the current location', () => {
    expect(breadcrumbTrail('/software')).toEqual([{ label: 'Software', to: undefined }, { label: 'Versions' }]);
  });

  it('links sibling-path tabs to the page home', () => {
    expect(breadcrumbTrail('/tasks')).toEqual([{ label: 'Delegator', to: '/assignments' }, { label: 'Tasks' }]);
    expect(breadcrumbTrail('/assignments')[0]).toEqual({ label: 'Delegator', to: undefined });
  });

  it('falls back to the parent label for tabs without an entry', () => {
    expect(breadcrumbTrail('/settings/users')).toEqual([{ label: 'Settings' }]);
    expect(breadcrumbTrail('/monitoring/configure/suppressions')).toEqual([
      { label: 'Monitoring', to: '/monitoring' },
      { label: 'Configure' },
    ]);
    expect(breadcrumbTrail('/network-tools/traffic/timeline')).toEqual([
      { label: 'Network Tools', to: '/network-tools' },
      { label: 'Traffic Analysis' },
    ]);
  });

  it('parents detail routes under their list page', () => {
    expect(breadcrumbTrail('/devices/42')).toEqual([
      { label: 'Inventory', to: '/inventory' },
      { label: 'Device Detail' },
    ]);
    expect(breadcrumbTrail('/dashboards/7')).toEqual([
      { label: 'Dashboards', to: '/dashboards' },
      { label: 'Dashboard' },
    ]);
  });
});
