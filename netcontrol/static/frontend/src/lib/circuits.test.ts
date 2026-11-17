import { describe, expect, it } from 'vitest';

import type { CircuitTermination } from '@/api/circuits';

import {
  circuitStatusLabel,
  circuitStatusTone,
  formatBps,
  formatKbps,
  isValidDate,
  parseKbps,
  terminationDraft,
  terminationErrors,
  terminationInput,
  terminationOf,
  terminationSummary,
} from './circuits';

const TERM: CircuitTermination = {
  id: 7,
  circuit_id: 3,
  term_side: 'A',
  site_id: 2,
  site_name: 'Site One',
  provider_network_id: null,
  provider_network_name: null,
  host_id: 5,
  hostname: 'edge-r1',
  interface_name: 'Gi0/1',
  port_speed_kbps: 1_000_000,
  upstream_speed_kbps: null,
  xconnect_id: 'XC-1',
  pp_info: '',
  description: '',
  created_by: 'admin',
  created_at: '',
  updated_at: '',
  updated_by: 'admin',
};

describe('circuit helpers', () => {
  it('labels statuses', () => {
    expect(circuitStatusLabel('active')).toBe('Active');
    expect(circuitStatusTone('offline')).toBe('danger');
    expect(circuitStatusLabel('other')).toBe('other');
    expect(circuitStatusTone('other')).toBe('neutral');
  });

  it('formats rates', () => {
    expect(formatKbps(null)).toBe('-');
    expect(formatKbps(512)).toBe('512 kbps');
    expect(formatKbps(100_000)).toBe('100 Mbps');
    expect(formatKbps(1_500_000)).toBe('1.5 Gbps');
    expect(formatKbps(2_000_000_000)).toBe('2 Tbps');
    expect(formatBps(800)).toBe('800 bps');
    expect(formatBps(2_000_000)).toBe('2 Mbps');
  });

  it('parses kbps', () => {
    expect(parseKbps(' ')).toBeNull();
    expect(parseKbps('1000')).toBe(1000);
    expect(parseKbps('1.5')).toBeUndefined();
    expect(parseKbps('-1')).toBeUndefined();
    expect(parseKbps('99999999999')).toBeUndefined();
  });

  it('summarises terminations', () => {
    expect(terminationSummary(undefined)).toBe('-');
    expect(terminationSummary(TERM)).toBe('Site One · edge-r1 Gi0/1');
    expect(terminationSummary({ ...TERM, hostname: null, site_name: null, provider_network_name: 'Backbone' })).toBe(
      'Backbone',
    );
    expect(terminationOf({ terminations: [TERM] }, 'A')).toBe(TERM);
    expect(terminationOf({ terminations: [TERM] }, 'Z')).toBeUndefined();
  });

  it('round-trips a termination draft', () => {
    const draft = terminationDraft(TERM);
    expect(draft).toMatchObject({ enabled: true, kind: 'site', port_speed: '1000000', upstream_speed: '' });
    expect(terminationErrors('A', draft)).toEqual({});
    expect(terminationInput('A', draft)).toEqual({
      term_side: 'A',
      site_id: 2,
      provider_network_id: null,
      host_id: 5,
      interface_name: 'Gi0/1',
      port_speed_kbps: 1_000_000,
      upstream_speed_kbps: null,
      xconnect_id: 'XC-1',
      pp_info: '',
      description: '',
    });
    expect(terminationDraft(undefined).enabled).toBe(false);
    expect(terminationErrors('Z', terminationDraft(undefined))).toEqual({});
  });

  it('checks a draft locally', () => {
    const draft = { ...terminationDraft(undefined), enabled: true, interface_name: 'Gi0/2', port_speed: 'fast' };
    expect(terminationErrors('Z', draft)).toEqual({
      'terminations.Z.site_id': 'Choose a site.',
      'terminations.Z.interface_name': 'Choose the device the interface belongs to.',
      'terminations.Z.port_speed_kbps': 'Port speed must be a whole number of kbps.',
    });
    const network = { ...draft, kind: 'network' as const, interface_name: '', port_speed: '', upstream_speed: 'x' };
    expect(terminationErrors('Z', network)).toEqual({
      'terminations.Z.provider_network_id': 'Choose a provider network.',
      'terminations.Z.upstream_speed_kbps': 'Upstream speed must be a whole number of kbps.',
    });
    // The interface is dropped when no device is chosen; only the chosen end is sent.
    expect(terminationInput('Z', { ...draft, site_id: 4, provider_network_id: 9 })).toMatchObject({
      site_id: 4,
      provider_network_id: null,
      interface_name: '',
    });
  });

  it('validates dates', () => {
    expect(isValidDate('')).toBe(true);
    expect(isValidDate('2026-02-28')).toBe(true);
    expect(isValidDate('2026-02-30')).toBe(false);
    expect(isValidDate('2026-2-3')).toBe(false);
  });
});
