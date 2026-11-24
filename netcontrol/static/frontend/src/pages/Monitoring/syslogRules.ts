// Pure helpers of Monitoring -> Configure -> Syslog Rules, kept apart from
// the component so they can be unit tested (component files may only export
// components). Also used by the Suppressions tab for the syslog metrics.

import type {
  RuleSettingsBody,
  SyslogActivity,
  SyslogMatchType,
  SyslogRule,
  SyslogRuleActivity,
  SyslogRuleBody,
  SyslogSeverity,
  SyslogUnmatchedGroup,
  TrapCondition,
  TrapConditionOp,
  TrapMatch,
  TrapRuleBody,
} from '@/api/syslogRules';
import { countLabel, formatCount } from '@/lib/formatCount';

export const SYSLOG_SEVERITY_OPTIONS: { value: SyslogSeverity; label: string }[] = [
  { value: 'info', label: 'Info' },
  { value: 'warning', label: 'Warning' },
  { value: 'critical', label: 'Critical' },
];

export const SYSLOG_MATCH_TYPES: { value: SyslogMatchType; label: string; hint: string }[] = [
  { value: 'tag', label: 'Tag', hint: 'Comma separated tags, e.g. SPANTREE-2-BLOCK_BPDUGUARD or UI_COMMIT_COMPLETED. The severity digit is ignored.' },
  { value: 'contains', label: 'Contains', hint: 'Text anywhere in the message, ignoring case.' },
  { value: 'regex', label: 'Regex', hint: 'RE2 pattern, ignoring case. A group named instance (or the first group) names the interface or neighbor.' },
];

/**
 * The suppression metrics of the built-in syslog rules: `syslog_<key>`. A
 * custom rule's metric is `syslog_custom_<id>`.
 */
export const SYSLOG_BUILTIN_METRICS: { value: string; label: string }[] = [
  { value: 'syslog_link_flap', label: 'Syslog: Interface flapping' },
  { value: 'syslog_ospf_neighbor', label: 'Syslog: OSPF neighbor down' },
  { value: 'syslog_bgp_neighbor', label: 'Syslog: BGP neighbor down' },
  { value: 'syslog_power_supply', label: 'Syslog: Power supply fault' },
  { value: 'syslog_fan', label: 'Syslog: Fan fault' },
  { value: 'syslog_module', label: 'Syslog: Module down' },
  { value: 'syslog_temperature', label: 'Syslog: Temperature alarm' },
  { value: 'syslog_ha_switchover', label: 'Syslog: HA failover or switchover' },
  { value: 'syslog_device_restart', label: 'Syslog: Device restarted' },
  { value: 'syslog_auth_failure', label: 'Syslog: Repeated login failures' },
  { value: 'syslog_stp_root_change', label: 'Syslog: Spanning tree root changed' },
  { value: 'syslog_stp_topology_change', label: 'Syslog: Spanning tree topology changes' },
  { value: 'syslog_stp_guard', label: 'Syslog: Spanning tree guard blocking a port' },
  { value: 'syslog_port_err_disabled', label: 'Syslog: Port error-disabled' },
  { value: 'syslog_port_security', label: 'Syslog: Port security violation' },
  { value: 'syslog_storm_control', label: 'Syslog: Traffic storm' },
  { value: 'syslog_mac_flap', label: 'Syslog: MAC address flapping' },
  { value: 'syslog_duplex_mismatch', label: 'Syslog: Duplex mismatch' },
  { value: 'syslog_hsrp_state', label: 'Syslog: HSRP failover' },
  { value: 'syslog_eigrp_neighbor', label: 'Syslog: EIGRP neighbor down' },
  { value: 'syslog_isis_adjacency', label: 'Syslog: IS-IS adjacency down' },
  { value: 'syslog_ipsec_tunnel', label: 'Syslog: IPsec tunnel down' },
  { value: 'syslog_ip_sla', label: 'Syslog: IP SLA probe down' },
  { value: 'syslog_poe_fault', label: 'Syslog: PoE fault' },
  { value: 'syslog_optic_power', label: 'Syslog: Optic light level out of range' },
  { value: 'syslog_aaa_server', label: 'Syslog: AAA server not responding' },
  { value: 'syslog_ntp_sync', label: 'Syslog: NTP synchronization lost' },
  { value: 'syslog_license_expiry', label: 'Syslog: License expiring or expired' },
  { value: 'syslog_certificate_expiry', label: 'Syslog: Certificate expiring or expired' },
  { value: 'syslog_software_fault', label: 'Syslog: Software crash or memory failure' },
];

/**
 * The suppression metrics of the built-in SNMP trap rules: `trap_<key>`
 * (netcontrol/trap_rules.py). Their own family: a suppression of
 * `syslog_<key>` or of a polled metric does not cover them.
 */
export const TRAP_BUILTIN_METRICS: { value: string; label: string }[] = [
  { value: 'trap_link_down', label: 'Trap: Interface down' },
  { value: 'trap_module', label: 'Trap: Module down' },
  { value: 'trap_power_supply', label: 'Trap: Power supply fault' },
  { value: 'trap_fan', label: 'Trap: Fan fault' },
  { value: 'trap_temperature', label: 'Trap: Temperature alarm' },
  { value: 'trap_bgp_neighbor', label: 'Trap: BGP neighbor down' },
  { value: 'trap_ospf_neighbor', label: 'Trap: OSPF neighbor down' },
  { value: 'trap_ha_switchover', label: 'Trap: HA failover or switchover' },
  { value: 'trap_device_restart', label: 'Trap: Device or agent restarted' },
  { value: 'trap_snmp_auth_failure', label: 'Trap: SNMP authentication failures' },
  { value: 'trap_stp_root_change', label: 'Trap: Spanning tree root changed' },
  { value: 'trap_stp_topology_change', label: 'Trap: Spanning tree topology changes' },
  { value: 'trap_port_err_disabled', label: 'Trap: Port error-disabled' },
  { value: 'trap_port_security', label: 'Trap: Port security violation' },
  { value: 'trap_mac_flap', label: 'Trap: MAC address flapping' },
  { value: 'trap_hsrp_state', label: 'Trap: HSRP failover' },
  { value: 'trap_eigrp_neighbor', label: 'Trap: EIGRP neighbor down' },
  { value: 'trap_isis_adjacency', label: 'Trap: IS-IS adjacency down' },
  { value: 'trap_ipsec_tunnel', label: 'Trap: IPsec tunnel down' },
  { value: 'trap_ip_sla', label: 'Trap: IP SLA probe down' },
  { value: 'trap_poe_fault', label: 'Trap: PoE fault' },
];

/** 600 -> "10 min", 3600 -> "1 h", 45 -> "45 s". */
export function formatSeconds(seconds: number): string {
  if (seconds > 0 && seconds % 3600 === 0) return `${seconds / 3600} h`;
  if (seconds > 0 && seconds % 60 === 0) return `${seconds / 60} min`;
  return `${seconds} s`;
}

/** "Every match" or "3 within 10 min". */
export function thresholdLabel(rule: Pick<SyslogRule, 'threshold_count' | 'threshold_window_seconds'>): string {
  if (rule.threshold_count <= 1) return 'Every match';
  return `${rule.threshold_count} within ${formatSeconds(rule.threshold_window_seconds)}`;
}

/** When an alert of the rule resolves without a clear message. */
export function autoResolveLabel(minutes: number): string {
  return minutes > 0 ? `After ${formatSeconds(minutes * 60)} quiet` : 'Clear message only';
}

/** What a repoll reason from the test endpoint means. */
export function repollLabel(reason: string): string {
  if (reason === 'interface_down') return 'Re-poll in 5 s (interface down)';
  if (reason === 'module') return 'Re-poll in 5 s (module down or back online)';
  if (reason === 'reload') return 'Re-poll in 30 s (reload)';
  if (reason === 'restart') return 'Re-poll in 5 s (restart)';
  if (reason === 'state_change') return 'Re-poll in 5 s (HA switchover or failover)';
  return '';
}

const RECOLLECT_REASONS: Record<string, string> = {
  gateway: 'a gateway alarm',
  carp: 'a CARP transition',
  vpn: 'a VPN tunnel up or down',
  config: 'a configuration save',
};

/** What a recollect reason from the test endpoint means. */
export function recollectLabel(reason: string | undefined): string {
  // A Suricata alert line reads the IDS alerts only, not the whole source.
  if (reason === 'ids') return 'From an OPNsense firewall: reads its IDS alerts in 5 s (a Suricata alert)';
  const why = reason ? RECOLLECT_REASONS[reason] : undefined;
  return why ? `From an OPNsense firewall: collects its topology source in 5 s (${why})` : '';
}

/** The form fields every custom rule (syslog or trap) has (`RuleSettingsFields`). */
export interface RuleSettingsForm {
  name: string;
  enabled: boolean;
  severity: SyslogSeverity;
  threshold_count: string;
  threshold_window_seconds: string;
  auto_resolve_minutes: string;
}

export interface SyslogRuleForm extends RuleSettingsForm {
  match_type: SyslogMatchType;
  pattern: string;
  clear_pattern: string;
}

const EMPTY_RULE_SETTINGS: RuleSettingsForm = {
  name: '',
  enabled: true,
  severity: 'warning',
  threshold_count: '1',
  threshold_window_seconds: '300',
  auto_resolve_minutes: '0',
};

export const EMPTY_SYSLOG_RULE_FORM: SyslogRuleForm = {
  ...EMPTY_RULE_SETTINGS,
  match_type: 'contains',
  pattern: '',
  clear_pattern: '',
};

function asSeverity(value: string): SyslogSeverity {
  return SYSLOG_SEVERITY_OPTIONS.some((o) => o.value === value) ? (value as SyslogSeverity) : 'warning';
}

function asMatchType(value: string): SyslogMatchType {
  return SYSLOG_MATCH_TYPES.some((o) => o.value === value) ? (value as SyslogMatchType) : 'contains';
}

function settingsFormFromRule(rule: SyslogRule): RuleSettingsForm {
  return {
    name: rule.name,
    enabled: rule.enabled,
    severity: asSeverity(rule.severity),
    threshold_count: String(rule.threshold_count),
    threshold_window_seconds: String(rule.threshold_window_seconds),
    auto_resolve_minutes: String(rule.auto_resolve_minutes),
  };
}

/** The form of a stored custom rule. */
export function formFromRule(rule: SyslogRule): SyslogRuleForm {
  return {
    ...settingsFormFromRule(rule),
    match_type: asMatchType(rule.match_type),
    pattern: rule.pattern,
    clear_pattern: rule.clear_pattern,
  };
}

function wholeNumber(value: string, fallback: number): number {
  const n = Number(value.trim());
  return value.trim() !== '' && Number.isInteger(n) ? n : fallback;
}

function settingsBodyFromForm(form: RuleSettingsForm): RuleSettingsBody {
  return {
    name: form.name.trim(),
    enabled: form.enabled,
    severity: form.severity,
    threshold_count: wholeNumber(form.threshold_count, 1),
    threshold_window_seconds: wholeNumber(form.threshold_window_seconds, 300),
    auto_resolve_minutes: wholeNumber(form.auto_resolve_minutes, 0),
  };
}

/** The API body of the form (the server validates ranges and patterns). */
export function bodyFromForm(form: SyslogRuleForm): SyslogRuleBody {
  return {
    ...settingsBodyFromForm(form),
    match_type: form.match_type,
    pattern: form.pattern.trim(),
    clear_pattern: form.clear_pattern.trim(),
  };
}

// --- Custom SNMP trap rules (Monitoring -> Configure -> Syslog Rules, trap section) ---

export const TRAP_CONDITION_OPS: { value: TrapConditionOp; label: string }[] = [
  { value: 'equals', label: 'equals' },
  { value: 'contains', label: 'contains' },
  { value: 'regex', label: 'matches (RE2)' },
];

export interface TrapRuleForm extends RuleSettingsForm {
  pattern: string;
  clear_pattern: string;
  conditions: TrapCondition[];
  clear_conditions: TrapCondition[];
  instance_object: string;
  instance_part: 'value' | 'index';
}

export const EMPTY_TRAP_RULE_FORM: TrapRuleForm = {
  ...EMPTY_RULE_SETTINGS,
  pattern: '',
  clear_pattern: '',
  conditions: [],
  clear_conditions: [],
  instance_object: '',
  instance_part: 'value',
};

export const EMPTY_TRAP_CONDITION: TrapCondition = { object: '', op: 'equals', value: '' };

/** The form of a stored custom trap rule. */
export function trapFormFromRule(rule: SyslogRule): TrapRuleForm {
  const match = rule.trap_match;
  return {
    ...settingsFormFromRule(rule),
    pattern: rule.pattern,
    clear_pattern: rule.clear_pattern,
    conditions: match?.conditions ?? [],
    clear_conditions: match?.clear_conditions ?? [],
    instance_object: match?.instance.object ?? '',
    instance_part: match?.instance.part ?? 'value',
  };
}

function cleanConditions(conditions: TrapCondition[]): TrapCondition[] {
  // A row left with neither a varbind nor a value is an unused one.
  return conditions
    .map((c) => ({ object: c.object.trim(), op: c.op, value: c.value.trim() }))
    .filter((c) => c.object !== '' || c.value !== '');
}

/** The API body of a trap rule form (the server validates the traps and conditions). */
export function trapBodyFromForm(form: TrapRuleForm): TrapRuleBody {
  const clearPattern = form.clear_pattern.trim();
  return {
    ...settingsBodyFromForm(form),
    pattern: form.pattern.trim(),
    clear_pattern: clearPattern,
    trap_match: {
      conditions: cleanConditions(form.conditions),
      // Clearing conditions without a clearing trap would be refused.
      clear_conditions: clearPattern ? cleanConditions(form.clear_conditions) : [],
      instance: { object: form.instance_object.trim(), part: form.instance_part },
    },
  };
}

/** A condition as one line: `ifAdminStatus equals up`. */
export function conditionLabel(c: TrapCondition): string {
  return `${c.object} ${TRAP_CONDITION_OPS.find((o) => o.value === c.op)?.label ?? c.op} ${c.value}`;
}

/** What names a trap rule's instance: "Per device", or the varbind's value / index. */
export function trapInstanceLabel(match: TrapMatch | undefined): string {
  const object = match?.instance.object ?? '';
  if (!object) return 'Per device';
  return match?.instance.part === 'index' ? `Index of ${object}` : `Value of ${object}`;
}

/**
 * The varbinds of the trap tester, one per line, `OID = value` (or `OID value`);
 * blank lines are skipped and the value may be empty.
 */
export function parseVarbindLines(text: string): [string, string][] {
  const out: [string, string][] = [];
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    const eq = line.indexOf('=');
    if (eq >= 0) {
      out.push([line.slice(0, eq).trim(), line.slice(eq + 1).trim()]);
      continue;
    }
    const space = line.search(/\s/);
    out.push(space < 0 ? [line, ''] : [line.slice(0, space), line.slice(space).trim()]);
  }
  return out;
}

// --- Received messages (GET /monitoring/syslog-rules/activity) ---

/** The windows the activity scan offers, in hours (the API takes 1..168). */
export const SYSLOG_ACTIVITY_WINDOWS: { hours: number; label: string }[] = [
  { hours: 1, label: '1 h' },
  { hours: 24, label: '24 h' },
  { hours: 168, label: '7 days' },
];

export const DEFAULT_SYSLOG_ACTIVITY_HOURS = 24;

/** 24 -> "24 h", 168 -> "7 days". */
export function activityWindowLabel(hours: number): string {
  return SYSLOG_ACTIVITY_WINDOWS.find((w) => w.hours === hours)?.label
    ?? (hours % 24 === 0 ? `${hours / 24} days` : `${hours} h`);
}

/** A rule's matches in the window; zeros when the scan saw none. */
export interface RuleMatchCounts {
  raised: number;
  /** Only shown when the rule can clear and cleared at least once. */
  cleared: number | null;
  hosts: number;
  last_at: string;
}

/** The activity of each rule by `SyslogRule.key`. */
export function activityByKey(activity: Pick<SyslogActivity, 'rules'> | undefined): Map<string, SyslogRuleActivity> {
  return new Map((activity?.rules ?? []).map((r) => [r.key, r]));
}

function hasClearPattern(rule: Pick<SyslogRule, 'builtin' | 'clear_tags' | 'clear_pattern'>): boolean {
  return rule.builtin ? rule.clear_tags.length > 0 : rule.clear_pattern.trim() !== '';
}

/** What the Matched and Last match columns of a rule show. */
export function ruleMatchCounts(
  rule: Pick<SyslogRule, 'key' | 'builtin' | 'clear_tags' | 'clear_pattern'>,
  byKey: Map<string, SyslogRuleActivity>,
): RuleMatchCounts {
  const a = byKey.get(rule.key);
  if (!a) return { raised: 0, cleared: null, hosts: 0, last_at: '' };
  return {
    raised: a.raised,
    cleared: hasClearPattern(rule) && a.cleared > 0 ? a.cleared : null,
    hosts: a.hosts,
    last_at: a.last_at,
  };
}

/** What names an unmatched group: its tag, else its program, else neither. */
export function unmatchedGroupLabel(group: Pick<SyslogUnmatchedGroup, 'tag' | 'program'>): {
  kind: 'tag' | 'program' | 'none';
  text: string;
} {
  if (group.tag) return { kind: 'tag', text: group.tag };
  if (group.program) return { kind: 'program', text: group.program };
  return { kind: 'none', text: '(no tag)' };
}

const RELATED_TRIGGERS: Record<string, string> = {
  config_change: 'Configuration change trigger',
  repoll: 'Re-poll trigger',
};

/**
 * The name of the built-in rule or trigger a group looks related to: the
 * rule's display name from the loaded list, else the key itself; '' for none.
 */
export function relatedName(related: string, rules: Pick<SyslogRule, 'key' | 'name'>[] | undefined): string {
  if (!related) return '';
  return RELATED_TRIGGERS[related] ?? rules?.find((r) => r.key === related)?.name ?? related;
}

/** The badge of an unmatched group that looks related to a rule or trigger; null for none. */
export function relatedBadge(
  group: Pick<SyslogUnmatchedGroup, 'related' | 'known_tag'>,
  rules: Pick<SyslogRule, 'key' | 'name'>[] | undefined,
): { text: string; title: string; tone: 'info' | 'warning' } | null {
  const name = relatedName(group.related, rules);
  if (!name) return null;
  if (group.known_tag) {
    return {
      text: `Tag of: ${name}`,
      title:
        'This tag is handled, but the text of these messages did not match the pattern. '
        + 'Usually the opposite event (an interface coming up); otherwise the wording differs on this platform.',
      tone: 'warning',
    };
  }
  return { text: `Related: ${name}`, title: 'A keyword hint from the message text, not a match', tone: 'info' };
}

/** The unmatched groups to list: all, or only those with a related hint. */
export function filterUnmatched<T extends Pick<SyslogUnmatchedGroup, 'related'>>(groups: T[], onlyRelated: boolean): T[] {
  return onlyRelated ? groups.filter((g) => g.related !== '') : groups;
}

/** A new custom rule's form and the tester's message, filled in before the modal opens. */
export interface SyslogRulePrefill {
  form: SyslogRuleForm;
  sample: string;
}

/** The custom-rule form (and tester message) a group's "Create rule" opens with. */
export function prefillFromGroup(group: Pick<SyslogUnmatchedGroup, 'tag' | 'program' | 'sample'>): SyslogRulePrefill {
  const base: SyslogRuleForm = { ...EMPTY_SYSLOG_RULE_FORM, severity: 'warning' };
  const label = unmatchedGroupLabel(group);
  const form: SyslogRuleForm =
    label.kind === 'tag'
      ? { ...base, name: group.tag.slice(0, 100), match_type: 'tag', pattern: group.tag }
      : label.kind === 'program'
        ? { ...base, name: group.program.slice(0, 100), match_type: 'contains', pattern: group.program }
        : { ...base, match_type: 'contains', pattern: '' };
  return { form, sample: group.sample };
}

export { countLabel };

/**
 * The one-line summary of a scan. The trigger numbers count messages, not
 * runs: several configuration messages start one backup, and re-polls are
 * rate limited per host.
 */
export function activitySummary(
  a: Pick<SyslogActivity, 'scanned' | 'matched' | 'unmatched' | 'unknown_source' | 'udp_stored_only' | 'triggers'>,
): string {
  const t = a.triggers;
  const storedOnly = a.udp_stored_only > 0 ? `${formatCount(a.udp_stored_only)} stored only (UDP), ` : '';
  return (
    `${countLabel(a.scanned, 'message', 'messages')} scanned: ${formatCount(a.matched)} matched, ${storedOnly}` +
    `${formatCount(a.unmatched)} unmatched, ${formatCount(a.unknown_source)} from unknown sources. ` +
    `Trigger messages: ${formatCount(t.config_change)} configuration change, ` +
    `${formatCount(t.repoll)} re-poll, ${formatCount(t.recollect)} OPNsense re-collection.`
  );
}

/** "By transport: 1,200 UDP, 40 TCP, 310 TLS."; '' when no inventory-host message was scanned. */
export function transportSummary(a: Pick<SyslogActivity, 'transports'>): string {
  const { udp, tcp, tls } = a.transports;
  if (udp + tcp + tls === 0) return '';
  return `By transport: ${formatCount(udp)} UDP, ${formatCount(tcp)} TCP, ${formatCount(tls)} TLS.`;
}

/**
 * What the scan says about syslog over UDP, or null for nothing:
 * - `ignored`: Act on UDP messages is off and UDP messages arrived (stored, not
 *   acted on), with how many of them a rule or trigger would have acted on.
 * - `remaining`: UDP is still acted on, some hosts already send over TCP or TLS,
 *   and these hosts still send over UDP. A UDP-only deployment gets no note.
 */
export function udpTransportNote(
  a: Pick<SyslogActivity, 'transports' | 'udp_hosts' | 'udp_actions' | 'udp_stored_only'>,
): { kind: 'ignored' | 'remaining'; text: string } | null {
  const { udp, tcp, tls } = a.transports;
  const hosts = countLabel(a.udp_hosts, 'host', 'hosts');
  if (!a.udp_actions) {
    if (udp === 0) return null;
    const verb = udp === 1 ? 'was' : 'were';
    const met =
      a.udp_stored_only === 0
        ? 'None of them meets a rule or trigger.'
        : `${formatCount(a.udp_stored_only)} of them ${a.udp_stored_only === 1 ? 'meets' : 'meet'} a rule or trigger `
          + 'and would have been acted on.';
    return {
      kind: 'ignored',
      text:
        `${countLabel(udp, 'message', 'messages')} from ${hosts} arrived over UDP and ${verb} stored but not acted on, `
        + `because Act on UDP messages is off. ${met}`,
    };
  }
  if (tcp + tls === 0 || a.udp_hosts === 0) return null;
  return {
    kind: 'remaining',
    text: `${countLabel(a.udp_hosts, 'host still sends', 'hosts still send')} syslog over UDP.`,
  };
}
