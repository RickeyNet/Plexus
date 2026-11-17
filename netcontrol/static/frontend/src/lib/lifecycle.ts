import type { ContractInput, ContractState, HardwareNotice, MilestoneKey, NoticeInput, SupportContract } from '@/api/lifecycle';
import { isValidDate } from '@/lib/circuits';
import type { Tone } from '@/lib/severity';

/** Limits the server applies (netcontrol/hardware_lifecycle.py, netcontrol/circuits.py). */
export const PART_NUMBER_MAX = 100;
export const PROVIDER_MAX = 100;
export const CONTRACT_ID_MAX = 100;
export const SUPPORT_LEVEL_MAX = 200;
export const URL_MAX = 500;
export const DESCRIPTION_MAX = 500;
export const COMMENTS_MAX = 10_000;
export const WARN_DAYS_MAX = 3650;

export type LifecycleStage = 'none' | 'supported' | MilestoneKey;
export type CoverageState = 'covered' | 'expiring' | 'expired' | 'not_started' | 'none';

/** The milestones in the order they fall due. */
export const MILESTONES: readonly { key: MilestoneKey; label: string; short: string }[] = [
  { key: 'end_of_sale', label: 'End of sale', short: 'End of sale' },
  { key: 'end_of_sw_maintenance', label: 'End of software maintenance', short: 'End of SW maintenance' },
  { key: 'end_of_security_fixes', label: 'End of security fixes', short: 'End of security fixes' },
  { key: 'end_of_support', label: 'Last date of support', short: 'End of support' },
];

export const STAGES: readonly { value: LifecycleStage; label: string; tone: Tone }[] = [
  { value: 'none', label: 'No notice', tone: 'neutral' },
  { value: 'supported', label: 'Announced', tone: 'info' },
  { value: 'end_of_sale', label: 'End of sale', tone: 'warning' },
  { value: 'end_of_sw_maintenance', label: 'End of SW maintenance', tone: 'warning' },
  { value: 'end_of_security_fixes', label: 'End of security fixes', tone: 'danger' },
  { value: 'end_of_support', label: 'End of support', tone: 'danger' },
];

export const COVERAGE: readonly { value: CoverageState; label: string; tone: Tone }[] = [
  { value: 'covered', label: 'Covered', tone: 'success' },
  { value: 'expiring', label: 'Expiring', tone: 'warning' },
  { value: 'expired', label: 'Expired', tone: 'danger' },
  { value: 'not_started', label: 'Not started', tone: 'info' },
  { value: 'none', label: 'No contract', tone: 'neutral' },
];

const CONTRACT_STATES: Record<ContractState, { label: string; tone: Tone }> = {
  covered: { label: 'Active', tone: 'success' },
  expiring: { label: 'Expiring', tone: 'warning' },
  expired: { label: 'Expired', tone: 'danger' },
  not_started: { label: 'Not started', tone: 'info' },
};

function labelOf(items: readonly { value: string; label: string; tone: Tone }[], value: string) {
  const found = items.find((i) => i.value === value);
  return found ? { label: found.label, tone: found.tone } : { label: value, tone: 'neutral' as Tone };
}

export function stageInfo(stage: string): { label: string; tone: Tone } {
  return labelOf(STAGES, stage);
}

export function coverageInfo(coverage: string): { label: string; tone: Tone } {
  return labelOf(COVERAGE, coverage);
}

export function contractStateInfo(state: string): { label: string; tone: Tone } {
  return CONTRACT_STATES[state as ContractState] ?? { label: state, tone: 'neutral' };
}

/** The status list filters; empty values are left out of the URL. */
export interface LifecycleFilter {
  stage?: LifecycleStage;
  coverage?: CoverageState;
  q?: string;
}

/** Days to a date as people read it: `today`, `in 12 days`, `3 days ago`; `-` for none. */
export function formatDays(days: number | null | undefined): string {
  if (days === null || days === undefined) return '-';
  if (days === 0) return 'today';
  const n = Math.abs(days);
  const unit = n === 1 ? 'day' : 'days';
  return days > 0 ? `in ${n.toLocaleString()} ${unit}` : `${n.toLocaleString()} ${unit} ago`;
}

/** A date with its distance: `2027-01-31 (in 75 days)`; `-` for none. */
export function formatDateWithDays(date: string | null | undefined, days: number | null | undefined): string {
  if (!date) return '-';
  return days === null || days === undefined ? date : `${date} (${formatDays(days)})`;
}

/** `1,500.00 USD`; `-` without a cost. */
export function formatCost(cost: string | null | undefined, currency: string): string {
  if (cost === null || cost === undefined || cost === '') return '-';
  const n = Number(cost);
  const amount = Number.isFinite(n)
    ? n.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })
    : cost;
  return currency ? `${amount} ${currency}` : amount;
}

/** What a notice is about: `Example Networks EX-1000` or `Part EX-LC-8`. */
export function noticeTarget(n: Pick<HardwareNotice, 'device_type_id' | 'device_type_model' | 'manufacturer_name' | 'part_number'>): string {
  if (n.device_type_id !== null) {
    return [n.manufacturer_name, n.device_type_model].filter(Boolean).join(' ') || `Device type #${n.device_type_id}`;
  }
  return `Part ${n.part_number}`;
}

/** How a notice applies to a device, for the device page. */
export function viaLabel(via: readonly string[] | undefined): string {
  const names: Record<string, string> = { device_type: 'device type', part_number: 'part number', module: 'module' };
  return (via ?? []).map((v) => names[v] ?? v).join(', ');
}

// ── Dialog drafts ──────────────────────────────────────────────────────────

export type NoticeTargetKind = 'device_type' | 'part_number';

export interface NoticeDraft {
  target: NoticeTargetKind;
  device_type_id: number | null;
  part_number: string;
  end_of_sale: string;
  end_of_sw_maintenance: string;
  end_of_security_fixes: string;
  end_of_support: string;
  documentation_url: string;
  comments: string;
}

export function noticeDraft(n: HardwareNotice | null): NoticeDraft {
  return {
    target: n && n.device_type_id === null ? 'part_number' : 'device_type',
    device_type_id: n?.device_type_id ?? null,
    part_number: n?.part_number ?? '',
    end_of_sale: n?.end_of_sale ?? '',
    end_of_sw_maintenance: n?.end_of_sw_maintenance ?? '',
    end_of_security_fixes: n?.end_of_security_fixes ?? '',
    end_of_support: n?.end_of_support ?? '',
    documentation_url: n?.documentation_url ?? '',
    comments: n?.comments ?? '',
  };
}

const URL_RE = /^https?:\/\/[^\s/$.?#]\S*$/i;

/** Per-field problems the server would refuse (it checks again). */
export function noticeErrors(d: NoticeDraft): Record<string, string> {
  const errors: Record<string, string> = {};
  if (d.target === 'device_type' && d.device_type_id === null) errors.device_type_id = 'Choose a device type.';
  if (d.target === 'part_number') {
    const pn = d.part_number.trim();
    if (!pn) errors.part_number = 'Enter a part number.';
    else if (/\s/.test(pn)) errors.part_number = 'Part number must not contain spaces.';
  }
  let previous: { label: string; date: string } | null = null;
  for (const m of MILESTONES) {
    const value = d[m.key].trim();
    if (!value) continue;
    if (!isValidDate(value)) {
      errors[m.key] = `${m.label} must be a date as YYYY-MM-DD.`;
      continue;
    }
    if (previous && value < previous.date) {
      errors[m.key] = `${m.label} must not be before ${previous.label.toLowerCase()} (${previous.date}).`;
    } else {
      previous = { label: m.label, date: value };
    }
  }
  const url = d.documentation_url.trim();
  if (url && !URL_RE.test(url)) errors.documentation_url = 'Documentation URL must start with http:// or https://.';
  return errors;
}

export function noticeInput(d: NoticeDraft): NoticeInput {
  const byType = d.target === 'device_type';
  return {
    device_type_id: byType ? d.device_type_id : null,
    part_number: byType ? '' : d.part_number.trim(),
    end_of_sale: d.end_of_sale.trim(),
    end_of_sw_maintenance: d.end_of_sw_maintenance.trim(),
    end_of_security_fixes: d.end_of_security_fixes.trim(),
    end_of_support: d.end_of_support.trim(),
    documentation_url: d.documentation_url.trim(),
    comments: d.comments.trim(),
  };
}

export interface ContractDraft {
  provider: string;
  contract_id: string;
  start_date: string;
  end_date: string;
  cost: string;
  currency: string;
  support_level: string;
  description: string;
  comments: string;
  host_ids: number[];
}

export function contractDraft(c: SupportContract | null): ContractDraft {
  return {
    provider: c?.provider ?? '',
    contract_id: c?.contract_id ?? '',
    start_date: c?.start_date ?? '',
    end_date: c?.end_date ?? '',
    cost: c?.cost ?? '',
    currency: c?.currency ?? '',
    support_level: c?.support_level ?? '',
    description: c?.description ?? '',
    comments: c?.comments ?? '',
    host_ids: c?.hosts.map((h) => h.id) ?? [],
  };
}

export function contractErrors(d: ContractDraft): Record<string, string> {
  const errors: Record<string, string> = {};
  if (!d.provider.trim()) errors.provider = 'Provider must not be empty.';
  if (!d.contract_id.trim()) errors.contract_id = 'Contract ID must not be empty.';
  for (const [key, label] of [
    ['start_date', 'Start date'],
    ['end_date', 'End date'],
  ] as const) {
    if (!isValidDate(d[key])) errors[key] = `${label} must be a date as YYYY-MM-DD.`;
  }
  const start = d.start_date.trim();
  const end = d.end_date.trim();
  if (!errors.start_date && !errors.end_date && start && end && end < start) {
    errors.end_date = 'End date must not be before the start date.';
  }
  const cost = d.cost.trim();
  if (cost && !/^\d{1,12}(\.\d{1,2})?$/.test(cost)) {
    errors.cost = 'Cost must be a number with at most two decimals.';
  }
  const currency = d.currency.trim();
  if (currency && !/^[A-Za-z]{3}$/.test(currency)) errors.currency = 'Currency must be a three-letter code such as USD.';
  return errors;
}

export function contractInput(d: ContractDraft): ContractInput {
  return {
    provider: d.provider.trim(),
    contract_id: d.contract_id.trim(),
    start_date: d.start_date.trim(),
    end_date: d.end_date.trim(),
    cost: d.cost.trim() || null,
    currency: d.currency.trim().toUpperCase(),
    support_level: d.support_level.trim(),
    description: d.description.trim(),
    comments: d.comments.trim(),
    host_ids: [...new Set(d.host_ids)].sort((a, b) => a - b),
  };
}
