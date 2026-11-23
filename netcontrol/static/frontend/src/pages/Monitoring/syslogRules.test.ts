import { describe, expect, it } from 'vitest';

import type { SyslogRule, SyslogUnmatchedGroup } from '@/api/syslogRules';

import {
  activityByKey,
  activitySummary,
  activityWindowLabel,
  autoResolveLabel,
  bodyFromForm,
  countLabel,
  EMPTY_SYSLOG_RULE_FORM,
  filterUnmatched,
  formatSeconds,
  formFromRule,
  prefillFromGroup,
  recollectLabel,
  relatedBadge,
  relatedName,
  repollLabel,
  ruleMatchCounts,
  SYSLOG_BUILTIN_METRICS,
  TRAP_BUILTIN_METRICS,
  thresholdLabel,
  transportSummary,
  udpTransportNote,
  unmatchedGroupLabel,
} from './syslogRules';

const RULE: SyslogRule = {
  id: 7,
  key: 'custom_7',
  metric: 'syslog_custom_7',
  name: 'BPDU guard',
  description: '',
  builtin: false,
  enabled: false,
  severity: 'critical',
  match_type: 'regex',
  pattern: 'BPDU on port (\\S+)',
  clear_pattern: '',
  tags: [],
  clear_tags: [],
  families: [],
  threshold_count: 2,
  threshold_window_seconds: 120,
  auto_resolve_minutes: 60,
  created_by: 'ops',
  created_at: '',
  updated_at: '',
};

describe('syslog rule labels', () => {
  it('formats a duration in its largest whole unit', () => {
    expect(formatSeconds(600)).toBe('10 min');
    expect(formatSeconds(3600)).toBe('1 h');
    expect(formatSeconds(45)).toBe('45 s');
    expect(formatSeconds(0)).toBe('0 s');
  });

  it('describes the threshold and the auto-resolve', () => {
    expect(thresholdLabel({ threshold_count: 1, threshold_window_seconds: 300 })).toBe('Every match');
    expect(thresholdLabel({ threshold_count: 3, threshold_window_seconds: 600 })).toBe('3 within 10 min');
    expect(autoResolveLabel(0)).toBe('Clear message only');
    expect(autoResolveLabel(30)).toBe('After 30 min quiet');
    expect(autoResolveLabel(1440)).toBe('After 24 h quiet');
  });

  it('names each re-poll reason', () => {
    expect(repollLabel('interface_down')).toContain('interface down');
    expect(repollLabel('reload')).toContain('30 s');
    expect(repollLabel('module')).toBe('Re-poll in 5 s (module down or back online)');
    expect(repollLabel('')).toBe('');
  });

  it('names each OPNsense re-collect reason', () => {
    expect(recollectLabel('gateway')).toContain('gateway alarm');
    expect(recollectLabel('carp')).toContain('CARP');
    expect(recollectLabel('vpn')).toContain('VPN');
    expect(recollectLabel('config')).toContain('configuration');
    expect(recollectLabel('ids')).toBe('From an OPNsense firewall: reads its IDS alerts in 5 s (a Suricata alert)');
    expect(recollectLabel('')).toBe('');
    expect(recollectLabel(undefined)).toBe('');
  });

  it('lists a suppression metric per built-in rule', () => {
    expect(SYSLOG_BUILTIN_METRICS.map((m) => m.value)).toEqual([
      'syslog_link_flap',
      'syslog_ospf_neighbor',
      'syslog_bgp_neighbor',
      'syslog_power_supply',
      'syslog_fan',
      'syslog_module',
      'syslog_auth_failure',
    ]);
  });

  it('lists a suppression metric per built-in trap rule, in their own trap_ family', () => {
    expect(TRAP_BUILTIN_METRICS.map((m) => m.value)).toEqual([
      'trap_link_down',
      'trap_module',
      'trap_power_supply',
      'trap_fan',
      'trap_temperature',
      'trap_bgp_neighbor',
      'trap_ospf_neighbor',
      'trap_ha_switchover',
      'trap_device_restart',
      'trap_snmp_auth_failure',
    ]);
    expect(TRAP_BUILTIN_METRICS.every((m) => m.label.startsWith('Trap: '))).toBe(true);
  });
});

describe('syslog rule form', () => {
  it('round-trips a stored rule', () => {
    const form = formFromRule(RULE);
    expect(form.threshold_count).toBe('2');
    expect(bodyFromForm(form)).toEqual({
      name: 'BPDU guard',
      enabled: false,
      match_type: 'regex',
      pattern: 'BPDU on port (\\S+)',
      clear_pattern: '',
      severity: 'critical',
      threshold_count: 2,
      threshold_window_seconds: 120,
      auto_resolve_minutes: 60,
    });
  });

  it('trims text and falls back on blank or fractional numbers', () => {
    const body = bodyFromForm({
      ...EMPTY_SYSLOG_RULE_FORM,
      name: '  Err-disable ',
      pattern: ' err-disabled ',
      threshold_count: '',
      threshold_window_seconds: '1.5',
      auto_resolve_minutes: '15',
    });
    expect([body.name, body.pattern, body.threshold_count, body.threshold_window_seconds, body.auto_resolve_minutes]).toEqual([
      'Err-disable',
      'err-disabled',
      1,
      300,
      15,
    ]);
  });

  it('keeps unknown stored values selectable as defaults', () => {
    const form = formFromRule({ ...RULE, severity: 'major', match_type: 'builtin' });
    expect([form.severity, form.match_type]).toEqual(['warning', 'contains']);
  });
});

const BUILTIN: SyslogRule = {
  ...RULE,
  id: null,
  key: 'link_flap',
  metric: 'syslog_link_flap',
  name: 'Interface flapping',
  builtin: true,
  match_type: 'builtin',
  pattern: '',
  tags: ['LINK-UPDOWN'],
  clear_tags: ['LINK-UP'],
};

const GROUP: SyslogUnmatchedGroup = {
  tag: 'SEC-IPACCESSLOGP',
  raw_tag: 'SEC-6-IPACCESSLOGP',
  program: '',
  count: 500,
  hosts: 3,
  device_types: ['cisco_ios'],
  last_at: '2026-01-02T03:04:05',
  sample: '%SEC-6-IPACCESSLOGP: list 101 denied tcp 192.0.2.5(1234) -> 198.51.100.7(22), 1 packet',
  related: '',
  known_tag: false,
};

describe('syslog rule activity', () => {
  const byKey = activityByKey({
    rules: [
      { key: 'link_flap', raised: 4, cleared: 2, hosts: 2, last_at: '2026-01-02T03:04:05' },
      { key: 'custom_7', raised: 1, cleared: 5, hosts: 1, last_at: '2026-01-02T01:00:00' },
    ],
  });

  it('labels each window', () => {
    expect(activityWindowLabel(1)).toBe('1 h');
    expect(activityWindowLabel(24)).toBe('24 h');
    expect(activityWindowLabel(168)).toBe('7 days');
    expect(activityWindowLabel(48)).toBe('2 days');
    expect(activityWindowLabel(5)).toBe('5 h');
  });

  it('merges a rule with its matches, and shows clears only for a rule that can clear', () => {
    expect(ruleMatchCounts(BUILTIN, byKey)).toEqual({ raised: 4, cleared: 2, hosts: 2, last_at: '2026-01-02T03:04:05' });
    // The custom rule has no clear pattern, so its clear count is not shown.
    expect(ruleMatchCounts(RULE, byKey).cleared).toBeNull();
    expect(ruleMatchCounts({ ...RULE, clear_pattern: 'BPDU cleared' }, byKey).cleared).toBe(5);
    expect(ruleMatchCounts({ ...BUILTIN, key: 'fan' }, byKey)).toEqual({ raised: 0, cleared: null, hosts: 0, last_at: '' });
    expect(activityByKey(undefined).size).toBe(0);
  });

  it('hides a zero clear count', () => {
    const map = activityByKey({ rules: [{ key: 'link_flap', raised: 3, cleared: 0, hosts: 1, last_at: '' }] });
    expect(ruleMatchCounts(BUILTIN, map).cleared).toBeNull();
  });

  it('names a group by tag, else program, else neither', () => {
    expect(unmatchedGroupLabel(GROUP)).toEqual({ kind: 'tag', text: 'SEC-IPACCESSLOGP' });
    expect(unmatchedGroupLabel({ tag: '', program: 'sshd' })).toEqual({ kind: 'program', text: 'sshd' });
    expect(unmatchedGroupLabel({ tag: '', program: '' })).toEqual({ kind: 'none', text: '(no tag)' });
  });

  it('names the rule or trigger a group looks related to', () => {
    expect(relatedName('link_flap', [BUILTIN])).toBe('Interface flapping');
    expect(relatedName('config_change', [BUILTIN])).toBe('Configuration change trigger');
    expect(relatedName('repoll', undefined)).toBe('Re-poll trigger');
    expect(relatedName('fan', undefined)).toBe('fan');
    expect(relatedName('', [BUILTIN])).toBe('');
  });

  it('badges a keyword hint and a handled tag differently', () => {
    expect(relatedBadge({ related: '', known_tag: false }, [BUILTIN])).toBeNull();
    const hint = relatedBadge({ related: 'link_flap', known_tag: false }, [BUILTIN]);
    expect(hint).toMatchObject({ text: 'Related: Interface flapping', tone: 'info' });
    const known = relatedBadge({ related: 'link_flap', known_tag: true }, [BUILTIN]);
    expect(known).toMatchObject({ text: 'Tag of: Interface flapping', tone: 'warning' });
    expect(known?.title).not.toBe(hint?.title);
  });

  it('filters to groups with a related hint', () => {
    const groups = [GROUP, { ...GROUP, tag: 'LINK-UPDOWN', related: 'link_flap' }];
    expect(filterUnmatched(groups, false)).toHaveLength(2);
    expect(filterUnmatched(groups, true).map((g) => g.tag)).toEqual(['LINK-UPDOWN']);
  });

  it('prefills a new rule from a tagged group', () => {
    const { form, sample } = prefillFromGroup(GROUP);
    expect(form).toEqual({ ...EMPTY_SYSLOG_RULE_FORM, name: 'SEC-IPACCESSLOGP', match_type: 'tag', pattern: 'SEC-IPACCESSLOGP', severity: 'warning' });
    expect(sample).toBe(GROUP.sample);
  });

  it('prefills a new rule from a program-only group and from an untagged group', () => {
    const program = prefillFromGroup({ tag: '', program: 'sshd', sample: 'sshd[42]: Accepted publickey for ops' });
    expect([program.form.name, program.form.match_type, program.form.pattern]).toEqual(['sshd', 'contains', 'sshd']);
    expect(program.sample).toBe('sshd[42]: Accepted publickey for ops');
    const none = prefillFromGroup({ tag: '', program: '', sample: 'kernel ready' });
    expect([none.form.name, none.form.match_type, none.form.pattern, none.form.severity]).toEqual(['', 'contains', '', 'warning']);
  });

  it('summarizes a scan in one line', () => {
    expect(countLabel(1, 'host', 'hosts')).toBe('1 host');
    expect(countLabel(0, 'host', 'hosts')).toBe('0 hosts');
    const line = activitySummary({
      scanned: 345,
      matched: 120,
      unmatched: 200,
      unknown_source: 25,
      udp_stored_only: 0,
      triggers: { config_change: 1, repoll: 10, recollect: 0 },
    });
    expect(line).toBe(
      '345 messages scanned: 120 matched, 200 unmatched, 25 from unknown sources. '
        + 'Trigger messages: 1 configuration change, 10 re-poll, 0 OPNsense re-collection.',
    );
  });

  it('counts apart the UDP messages that were stored only', () => {
    const line = activitySummary({
      scanned: 1345,
      matched: 120,
      unmatched: 200,
      unknown_source: 25,
      udp_stored_only: 1000,
      triggers: { config_change: 0, repoll: 0, recollect: 0 },
    });
    expect(line).toContain('1,345 messages scanned: 120 matched, 1,000 stored only (UDP), 200 unmatched, 25 from unknown sources.');
  });
});

describe('syslog transports', () => {
  const scan = (udp: number, tcp: number, tls: number, udpHosts: number, udpActions: boolean, storedOnly = 0) => ({
    transports: { udp, tcp, tls },
    udp_hosts: udpHosts,
    udp_actions: udpActions,
    udp_stored_only: storedOnly,
  });

  it('counts the messages per transport', () => {
    expect(transportSummary(scan(1200, 40, 310, 9, true))).toBe('By transport: 1,200 UDP, 40 TCP, 310 TLS.');
    expect(transportSummary(scan(0, 0, 0, 0, true))).toBe('');
  });

  it('says how many UDP messages were stored but not acted on while UDP actions are off', () => {
    expect(udpTransportNote(scan(1200, 40, 0, 3, false, 85))).toEqual({
      kind: 'ignored',
      text:
        '1,200 messages from 3 hosts arrived over UDP and were stored but not acted on, because Act on UDP messages is off. '
        + '85 of them meet a rule or trigger and would have been acted on.',
    });
    expect(udpTransportNote(scan(1, 0, 5, 1, false, 1))?.text).toBe(
      '1 message from 1 host arrived over UDP and was stored but not acted on, because Act on UDP messages is off. '
        + '1 of them meets a rule or trigger and would have been acted on.',
    );
    expect(udpTransportNote(scan(7, 0, 5, 2, false))?.text).toBe(
      '7 messages from 2 hosts arrived over UDP and were stored but not acted on, because Act on UDP messages is off. '
        + 'None of them meets a rule or trigger.',
    );
    expect(udpTransportNote(scan(0, 40, 5, 0, false))).toBeNull();
  });

  it('names the hosts still on UDP only once some hosts send over TCP or TLS', () => {
    expect(udpTransportNote(scan(500, 0, 20, 4, true))).toEqual({ kind: 'remaining', text: '4 hosts still send syslog over UDP.' });
    expect(udpTransportNote(scan(5, 10, 0, 1, true))?.text).toBe('1 host still sends syslog over UDP.');
    // A UDP-only deployment, and one that has moved every host, get no note.
    expect(udpTransportNote(scan(500, 0, 0, 4, true))).toBeNull();
    expect(udpTransportNote(scan(0, 10, 20, 0, true))).toBeNull();
  });
});
