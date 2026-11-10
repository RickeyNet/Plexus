import { describe, expect, it } from 'vitest';

import type { DeviceHealth } from '@/api/dashboard';

import { HEALTH_LABELS, SEVERITY_ORDER, countDeviceHealth } from './helpers';

const device = (over: Partial<DeviceHealth>): DeviceHealth => over as DeviceHealth;

describe('countDeviceHealth', () => {
  it('counts each device under its health status', () => {
    const counts = countDeviceHealth([
      device({ cpu_percent: 10, memory_percent: 20 }),
      device({ cpu_percent: 80 }),
      device({ cpu_percent: 95 }),
      device({ poll_status: 'error' }),
      device({}),
      device({ cpu_percent: 5 }),
    ]);
    expect(counts).toEqual({ healthy: 2, warning: 1, critical: 1, down: 1, unknown: 1 });
  });

  it('returns zeros for no devices', () => {
    expect(countDeviceHealth([])).toEqual({ healthy: 0, warning: 0, critical: 0, down: 0, unknown: 0 });
  });
});

describe('health labels and order', () => {
  it('has one label per status and sorts worst first', () => {
    expect(Object.keys(HEALTH_LABELS).sort()).toEqual(Object.keys(SEVERITY_ORDER).sort());
    expect(SEVERITY_ORDER.down).toBeLessThan(SEVERITY_ORDER.healthy);
  });
});
