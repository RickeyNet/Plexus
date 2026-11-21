/** Pure helpers of the OPNsense rules view (filtering, labels, tones). */
import type {
  OpnsenseAliasTables,
  OpnsenseAnalyzedRule,
  OpnsenseRuleEndpoint,
  OpnsenseRuleFinding,
  OpnsenseRuleFlag,
} from '@/api/opnsenseRules';
import type { Tone } from '@/lib/severity';

export const FLAG_LABELS: Record<OpnsenseRuleFlag, string> = {
  any_any: 'Any to any',
  shadowed: 'Shadowed',
  disabled: 'Disabled',
  missing_alias: 'Missing alias',
  unused: 'Unused',
  unused_90d: 'Unused long-term',
};

export const FLAG_TONES: Record<OpnsenseRuleFlag, Tone> = {
  any_any: 'danger',
  shadowed: 'warning',
  disabled: 'neutral',
  missing_alias: 'danger',
  unused: 'info',
  unused_90d: 'warning',
};

function daysText(days: number): string {
  return `${days.toLocaleString()} ${days === 1 ? 'day' : 'days'}`;
}

/**
 * The name of a flag on the summary chips and filters: the long-term unused
 * flag names the server's threshold (`Unused 90 days`).
 */
export function flagName(flag: OpnsenseRuleFlag, unusedDays: number | undefined): string {
  if (flag === 'unused_90d' && unusedDays) return `Unused ${daysText(unusedDays)}`;
  return FLAG_LABELS[flag];
}

/** Whether a host's device type is an OPNsense firewall. */
export function isOpnsenseDevice(deviceType: string | null | undefined): boolean {
  return (deviceType ?? '').toLowerCase().includes('opnsense');
}

export function actionTone(action: string): Tone {
  if (action === 'pass') return 'success';
  if (action === 'block' || action === 'reject') return 'danger';
  return 'neutral';
}

/** The label a flag shows on a rule: a shadowed rule names the rule that shadows it. */
export function flagLabel(rule: OpnsenseAnalyzedRule, flag: OpnsenseRuleFlag): string {
  if (flag === 'shadowed' && rule.shadowed_by != null) {
    return `Shadowed by #${rule.shadowed_by}${rule.shadow === 'conflicting' ? ' (opposite action)' : ''}`;
  }
  if (flag === 'missing_alias' && rule.missing_aliases.length) {
    return `Missing alias: ${rule.missing_aliases.join(', ')}`;
  }
  if (flag === 'unused_90d' && rule.history) {
    return `No hit in ${daysText(rule.history.idle_days)}`;
  }
  return FLAG_LABELS[flag];
}

/**
 * A rule's counter history as short lines: when it last matched (or that it
 * never did while tracked) and how long it has been tracked, with how many
 * days are left before the long-term unused check can flag it. [] without
 * history.
 */
export function historyLines(rule: OpnsenseAnalyzedRule, unusedDays: number | undefined): string[] {
  const history = rule.history;
  if (!history) return [];
  const lines = [
    history.last_hit_at
      ? `last hit ${history.idle_days ? `${daysText(history.idle_days)} ago` : 'today'}`
      : `no hit since tracking began`,
  ];
  const short = unusedDays != null && history.tracked_days < unusedDays;
  lines.push(
    `tracked for ${daysText(history.tracked_days)}` +
      (short ? ` (${daysText(unusedDays - history.tracked_days)} before the ${unusedDays}-day check)` : ''),
  );
  return lines;
}

/** A rule side as one line: `! lan net port 443`. */
export function endpointText(point: OpnsenseRuleEndpoint): string {
  return point.port && point.port !== 'any' ? `${point.text} port ${point.port}` : point.text;
}

/**
 * The aliases of a rule side the path trace resolves from their collected
 * pf table, one line each: `GeoBlock: pf table, 1,234 entries` (`truncated,
 * 9,999 of 50,000 entries read` when cut). Matched by name, ignoring case.
 */
export function aliasTableLines(point: OpnsenseRuleEndpoint, tables: OpnsenseAliasTables | undefined): string[] {
  const found = tables?.tables ?? {};
  const byName = new Map(Object.entries(found).map(([name, table]) => [name.toLowerCase(), table]));
  return point.aliases.flatMap((alias) => {
    const table = byName.get(alias.toLowerCase());
    if (!table) return [];
    const size = table.truncated
      ? `truncated, ${table.entry_count.toLocaleString()} of ${table.total.toLocaleString()} entries read`
      : `${table.entry_count.toLocaleString()} ${table.entry_count === 1 ? 'entry' : 'entries'}`;
    return [`${alias}: pf table, ${size}`];
  });
}

/** The interfaces a rule shows under (`*` for a floating rule on every interface). */
export function ruleInterfaces(rule: OpnsenseAnalyzedRule): string[] {
  return rule.zones.length ? rule.zones : ['*'];
}

export interface RuleFilter {
  /** An interface key, or '' for every interface. */
  iface: string;
  /** A flag every shown rule has, or '' for any. */
  flag: OpnsenseRuleFlag | '';
  /** Free text matched against the description, sides, aliases and number. */
  text: string;
}

export function filterRules(rules: OpnsenseAnalyzedRule[], filter: RuleFilter): OpnsenseAnalyzedRule[] {
  const text = filter.text.trim().toLowerCase();
  return rules.filter((rule) => {
    if (filter.iface) {
      const zones = ruleInterfaces(rule);
      if (!zones.includes(filter.iface) && !zones.includes('*')) return false;
    }
    if (filter.flag && !rule.flags.includes(filter.flag)) return false;
    if (!text) return true;
    const haystack = [
      String(rule.number),
      rule.description,
      rule.action,
      rule.protocol,
      endpointText(rule.source),
      endpointText(rule.destination),
      ...rule.source.aliases,
      ...rule.destination.aliases,
      ...rule.source.cidrs,
      ...rule.destination.cidrs,
    ]
      .join(' ')
      .toLowerCase();
    return haystack.includes(text);
  });
}

/** The counters of a rule as a short text; '' without counters. */
export function countersText(rule: OpnsenseAnalyzedRule): string {
  const stats = rule.stats;
  if (!stats) return '';
  const parts: string[] = [];
  if (stats.packets != null) parts.push(`${stats.packets.toLocaleString()} pkts`);
  if (stats.states != null) parts.push(`${stats.states.toLocaleString()} states`);
  return parts.join(' · ');
}

/** A side of a rule finding as one line: `lan net port 443`. */
function findingSide(text: string, port: string): string {
  return port && port !== 'any' ? `${text || 'any'} port ${port}` : text || 'any';
}

/**
 * A rule a configuration change made any-to-any or shadowed, as one line of
 * the backup comparison (what the rule change alert says).
 */
export function findingText(finding: OpnsenseRuleFinding): string {
  const rule =
    `#${finding.number} ${finding.action} ${findingSide(finding.source, finding.source_port)} → ` +
    `${findingSide(finding.destination, finding.destination_port)} ${finding.description}`.trimEnd();
  if (finding.kind === 'any_any') return `any to any: ${rule}`;
  const how = finding.shadow === 'conflicting' ? 'conflicting' : 'redundant';
  return `shadowed by #${finding.shadowed_by ?? '?'} (${how}): ${rule}`;
}

/** A changed value of a diff as text. */
export function changeText(value: unknown): string {
  if (value == null || value === '') return '-';
  if (Array.isArray(value)) return value.join(', ') || '-';
  if (typeof value === 'boolean') return value ? 'yes' : 'no';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}
