import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import type { VendorStatus } from '@/api/deviceDetail';

import { formatRuntime, upsBatteryTone, upsOutputTone } from './ups';
import { UpsStatusCard } from './UpsStatusCard';

// Invented values in the shape GET /api/monitoring/hosts/{id}/vendor-status returns.
const ON_BATTERY: VendorStatus = {
  host_id: 7,
  kind: 'apc_ups',
  polled_at: '2026-01-01 12:00:00',
  status: {
    model: 'Smart-UPS 1500',
    firmware: 'UPS 09.3 (ID18)',
    firmware_version: '9.3',
    serial: 'AS0000000001',
    output_status: 3,
    output_status_label: 'On battery',
    battery_status: 2,
    battery_status_label: 'Normal',
    battery_capacity_pct: 87,
    runtime_minutes: 23.5,
    output_load_pct: 41,
    battery_needs_replacing: true,
    nmc_model: 'AP9631',
    nmc_firmware: '6.8.2',
  },
};

describe('UpsStatusCard', () => {
  it('shows the state and identity of the UPS', () => {
    const html = renderToStaticMarkup(<UpsStatusCard vendor={ON_BATTERY} />);
    expect(html).toContain('On battery');
    expect(html).toContain('badge-warning');
    expect(html).toContain('Replace battery');
    expect(html).toContain('87%');
    expect(html).toContain('24 min');
    expect(html).toContain('41%');
    expect(html).toContain('Smart-UPS 1500');
    expect(html).toContain('UPS 09.3 (ID18)');
    expect(html).toContain('AP9631, firmware 6.8.2');
  });

  it('renders nothing before the first poll or for another kind', () => {
    expect(renderToStaticMarkup(<UpsStatusCard vendor={undefined} />)).toBe('');
    const none: VendorStatus = { host_id: 7, kind: '', status: {}, polled_at: '' };
    expect(renderToStaticMarkup(<UpsStatusCard vendor={none} />)).toBe('');
  });
});

describe('UPS state tones', () => {
  it('marks on battery as a warning and off or bypass as danger', () => {
    expect(upsOutputTone(2)).toBe('success');
    expect(upsOutputTone(3)).toBe('warning');
    expect(upsOutputTone(7)).toBe('danger');
    expect(upsOutputTone(10)).toBe('danger');
    expect(upsOutputTone(15)).toBe('neutral');
    expect(upsOutputTone(null)).toBe('neutral');
  });

  it('marks a low or failed battery as danger and a replacement as a warning', () => {
    expect(upsBatteryTone(2)).toBe('success');
    expect(upsBatteryTone(2, true)).toBe('warning');
    expect(upsBatteryTone(3)).toBe('danger');
    expect(upsBatteryTone(5)).toBe('danger');
    expect(upsBatteryTone(undefined)).toBe('neutral');
  });

  it('formats the runtime in minutes or hours', () => {
    expect(formatRuntime(null)).toBe('N/A');
    expect(formatRuntime(23.4)).toBe('23 min');
    expect(formatRuntime(65)).toBe('1 h 05 min');
  });
});
