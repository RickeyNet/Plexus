/** Pure helpers of the OPNsense rules view (filtering, labels, tones). */
import type { OpnsenseAnalyzedRule, OpnsenseRuleEndpoint, OpnsenseRuleFlag } from '@/api/opnsenseRules';
import type { Tone } from '@/lib/severity';

export const FLAG_LABELS: Record<OpnsenseRuleFlag, string> = {
  any_any: 'Any to any',
  shadowed: 'Shadowed',
  disabled: 'Disabled',
  missing_alias: 'Missing alias',
  unused: 'Unused',
};

export const FLAG_TONES: Record<OpnsenseRuleFlag, Tone> = {
  any_any: 'danger',
  shadowed: 'warning',
  disabled: 'neutral',
  missing_alias: 'danger',
  unused: 'info',
};

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
  return FLAG_LABELS[flag];
}

/** A rule side as one line: `! lan net port 443`. */
export function endpointText(point: OpnsenseRuleEndpoint): string {
  return point.port && point.port !== 'any' ? `${point.text} port ${point.port}` : point.text;
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

/** A changed value of a diff as text. */
export function changeText(value: unknown): string {
  if (value == null || value === '') return '-';
  if (Array.isArray(value)) return value.join(', ') || '-';
  if (typeof value === 'boolean') return value ? 'yes' : 'no';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}
