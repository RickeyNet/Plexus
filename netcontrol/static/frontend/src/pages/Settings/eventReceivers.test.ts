import { describe, expect, it } from 'vitest';

import type { EventReceiverConfig } from '@/api/settings';

import {
  filterlogSummary,
  receiverCounters,
  receiverSettings,
  saveSummary,
  validateReceiverPorts,
} from './eventReceivers';

function config(over: Partial<EventReceiverConfig> = {}): EventReceiverConfig {
  return {
    syslog_enabled: true,
    syslog_port: 1514,
    trap_enabled: true,
    trap_port: 10162,
    syslog_alerts: true,
    config_change_trigger: true,
    repoll_trigger: false,
    recollect_trigger: true,
    filterlog_evidence: true,
    syslog_running: true,
    trap_running: true,
    syslog_received: 1234,
    trap_received: 0,
    syslog_errors: 2,
    trap_errors: 0,
    syslog_last_message_at: '2026-06-15T11:58:00+00:00',
    trap_last_message_at: '',
    events_dropped: 0,
    ...over,
  };
}

describe('receiverSettings', () => {
  it('keeps only the saved settings', () => {
    expect(receiverSettings(config())).toEqual({
      syslog_enabled: true,
      syslog_port: 1514,
      trap_enabled: true,
      trap_port: 10162,
      syslog_alerts: true,
      config_change_trigger: true,
      repoll_trigger: false,
      recollect_trigger: true,
      filterlog_evidence: true,
    });
  });
});

describe('validateReceiverPorts', () => {
  it('accepts the defaults', () => {
    expect(validateReceiverPorts(config())).toEqual({});
  });

  it('rejects ports outside 1-65535 and non-integers', () => {
    expect(validateReceiverPorts(config({ syslog_port: 0 })).syslog_port).toBeTruthy();
    expect(validateReceiverPorts(config({ trap_port: 70000 })).trap_port).toBeTruthy();
    expect(validateReceiverPorts(config({ trap_port: 1.5 })).trap_port).toBeTruthy();
  });

  it('rejects the same port for both enabled receivers only', () => {
    expect(validateReceiverPorts(config({ trap_port: 1514 })).trap_port).toContain('different port');
    expect(validateReceiverPorts(config({ trap_port: 1514, trap_enabled: false }))).toEqual({});
  });
});

describe('saveSummary', () => {
  it('names each receiver state', () => {
    const text = saveSummary(config({ trap_running: false, syslog_enabled: true }));
    expect(text).toContain('Syslog listening on UDP 1514');
    expect(text).toContain('SNMP traps failed to start on UDP 10162');
    expect(saveSummary(config({ syslog_enabled: false, trap_enabled: false }))).toBe(
      'Receiver settings saved: Syslog off, SNMP traps off.',
    );
  });
});

describe('receiverCounters', () => {
  const now = Date.parse('2026-06-15T12:00:00Z');

  it('shows received count, last message age and unreadable count', () => {
    const items = receiverCounters(config(), 'syslog', now);
    expect(items.map((i) => i.label)).toEqual(['Received', 'Last message', 'Unreadable']);
    expect(items[0].value).toBe((1234).toLocaleString());
    expect(items[1].value).toBe('2m ago');
    expect(items[2].tone).toBe('warning');
  });

  it('says none yet before the first message', () => {
    const items = receiverCounters(config(), 'trap', now);
    expect(items[0].value).toBe('0');
    expect(items[1].value).toBe('None yet');
    expect(items[2].tone).toBeUndefined();
  });
});

describe('filterlogSummary', () => {
  it('counts the lines kept and dropped', () => {
    expect(filterlogSummary(config())).toBe('OPNsense firewall log lines since Plexus started: 0 counted, 0 dropped.');
    expect(filterlogSummary(config({ filterlog_received: 1200, filterlog_dropped: 3, filterlog_unknown_source: 2 }))).toBe(
      'OPNsense firewall log lines since Plexus started: 1,200 counted, 3 dropped (2 from addresses that are no inventory host).',
    );
  });
});
