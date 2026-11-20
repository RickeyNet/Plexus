// Pure helpers of Monitoring -> Configure -> Syslog Rules, kept apart from
// the component so they can be unit tested (component files may only export
// components). Also used by the Suppressions tab for the syslog metrics.

import type {
  SyslogActivity,
  SyslogMatchType,
  SyslogRule,
  SyslogRuleActivity,
  SyslogRuleBody,
  SyslogSeverity,
  SyslogUnmatchedGroup,
} from '@/api/syslogRules';
import { formatCount } from '@/lib/formatCount';

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
  { value: 'syslog_auth_failure', label: 'Syslog: Repeated login failures' },
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
  if (reason === 'reload') return 'Re-poll in 30 s (reload)';
  if (reason === 'restart') return 'Re-poll in 5 s (restart)';
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
  const why = reason ? RECOLLECT_REASONS[reason] : undefined;
  return why ? `From an OPNsense firewall: collects its topology source in 5 s (${why})` : '';
}

export interface SyslogRuleForm {
  name: string;
  enabled: boolean;
  match_type: SyslogMatchType;
  pattern: string;
  clear_pattern: string;
  severity: SyslogSeverity;
  threshold_count: string;
  threshold_window_seconds: string;
  auto_resolve_minutes: string;
}

export const EMPTY_SYSLOG_RULE_FORM: SyslogRuleForm = {
  name: '',
  enabled: true,
  match_type: 'contains',
  pattern: '',
  clear_pattern: '',
  severity: 'warning',
  threshold_count: '1',
  threshold_window_seconds: '300',
  auto_resolve_minutes: '0',
};

function asSeverity(value: string): SyslogSeverity {
  return SYSLOG_SEVERITY_OPTIONS.some((o) => o.value === value) ? (value as SyslogSeverity) : 'warning';
}

function asMatchType(value: string): SyslogMatchType {
  return SYSLOG_MATCH_TYPES.some((o) => o.value === value) ? (value as SyslogMatchType) : 'contains';
}

/** The form of a stored custom rule. */
export function formFromRule(rule: SyslogRule): SyslogRuleForm {
  return {
    name: rule.name,
    enabled: rule.enabled,
    match_type: asMatchType(rule.match_type),
    pattern: rule.pattern,
    clear_pattern: rule.clear_pattern,
    severity: asSeverity(rule.severity),
    threshold_count: String(rule.threshold_count),
    threshold_window_seconds: String(rule.threshold_window_seconds),
    auto_resolve_minutes: String(rule.auto_resolve_minutes),
  };
}

function wholeNumber(value: string, fallback: number): number {
  const n = Number(value.trim());
  return value.trim() !== '' && Number.isInteger(n) ? n : fallback;
}

/** The API body of the form (the server validates ranges and patterns). */
export function bodyFromForm(form: SyslogRuleForm): SyslogRuleBody {
  return {
    name: form.name.trim(),
    enabled: form.enabled,
    match_type: form.match_type,
    pattern: form.pattern.trim(),
    clear_pattern: form.clear_pattern.trim(),
    severity: form.severity,
    threshold_count: wholeNumber(form.threshold_count, 1),
    threshold_window_seconds: wholeNumber(form.threshold_window_seconds, 300),
    auto_resolve_minutes: wholeNumber(form.auto_resolve_minutes, 0),
  };
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

/** 1 -> "1 host", 1200 -> "1,200 hosts". */
export function countLabel(n: number, one: string, many: string): string {
  return `${formatCount(n)} ${n === 1 ? one : many}`;
}

/**
 * The one-line summary of a scan. The trigger numbers count messages, not
 * runs: several configuration messages start one backup, and re-polls are
 * rate limited per host.
 */
export function activitySummary(a: Pick<SyslogActivity, 'scanned' | 'matched' | 'unmatched' | 'unknown_source' | 'triggers'>): string {
  const t = a.triggers;
  return (
    `${countLabel(a.scanned, 'message', 'messages')} scanned: ${formatCount(a.matched)} matched, ` +
    `${formatCount(a.unmatched)} unmatched, ${formatCount(a.unknown_source)} from unknown sources. ` +
    `Trigger messages: ${formatCount(t.config_change)} configuration change, ` +
    `${formatCount(t.repoll)} re-poll, ${formatCount(t.recollect)} OPNsense re-collection.`
  );
}
