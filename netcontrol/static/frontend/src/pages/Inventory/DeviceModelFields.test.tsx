import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import type { DeviceRole, DeviceType, HostStatus } from '@/api/deviceModel';

import { DeviceModelFields } from './DeviceModelFields';

const TYPES: DeviceType[] = [
  { id: 1, manufacturer_id: 1, manufacturer: 'Acme', model: 'A-10', part_number: '', u_height: 1, description: '', host_count: 0 },
  {
    id: 2,
    manufacturer_id: 2,
    manufacturer: 'Example Networks',
    model: 'EX-4800',
    part_number: '',
    u_height: 1,
    description: '',
    host_count: 0,
  },
];
const ROLES: DeviceRole[] = [{ id: 5, name: 'Switch', color: 'teal', description: '', host_count: 0 }];
const STATUSES: HostStatus[] = [
  { id: 7, name: 'Active', color: 'green', description: '', is_default: true, host_count: 0 },
  { id: 8, name: 'Planned', color: 'blue', description: '', is_default: false, host_count: 0 },
];

function render(allowKeep: boolean, location: string | null = ''): string {
  const qc = new QueryClient();
  qc.setQueryData(['device-model', 'device-types', 'all'], TYPES);
  qc.setQueryData(['device-model', 'roles'], ROLES);
  qc.setQueryData(['device-model', 'statuses'], STATUSES);
  qc.setQueryData(['geo', 'sites'], [{ id: 3, name: 'Branch 1' }]);
  return renderToStaticMarkup(
    <QueryClientProvider client={qc}>
      <DeviceModelFields
        idPrefix="t"
        ids={{ device_type_id: '2', role_id: '', lifecycle_status_id: '7', site_id: allowKeep ? 'keep' : '' }}
        onIdChange={() => {}}
        location={location}
        onLocationChange={() => {}}
        allowKeep={allowKeep}
      />
    </QueryClientProvider>,
  );
}

describe('DeviceModelFields', () => {
  it('labels every control', () => {
    const html = render(false);
    for (const [id, label] of [
      ['t-device_type_id', 'Device type'],
      ['t-role_id', 'Role'],
      ['t-lifecycle_status_id', 'Lifecycle status'],
      ['t-site_id', 'Site'],
      ['t-location', 'Rack / room'],
    ]) {
      expect(html).toContain(`<label class="form-label" for="${id}">${label}</label>`);
    }
  });

  it('groups device types by manufacturer after a None choice', () => {
    const html = render(false);
    expect(html).toMatch(/<option value="">None<\/option><optgroup label="Acme"><option value="1">A-10<\/option><\/optgroup><optgroup label="Example Networks">/);
    expect(html).toContain('Active (default)');
    expect(html).not.toContain('Leave unchanged');
  });

  it('offers Leave unchanged first in bulk mode and disables rack / room until chosen', () => {
    const html = render(true, null);
    expect(html).toMatch(/<option value="keep">Leave unchanged<\/option><option value="">None<\/option>/);
    expect(html).toMatch(/<input id="t-location"[^>]*disabled=""/);
    expect(html).toContain('Change rack / room');
  });
});
