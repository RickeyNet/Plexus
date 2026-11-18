/**
 * Pure helpers for the Intended tab: the editors' request bodies and
 * validation, error and result wording, and the scope summaries and options.
 */
import { CustomDataError } from '@/api/customData';
import type {
  ConfigContextInput,
  ConfigTemplateInput,
  GenerateResult,
  IntendedScope,
  RenderError,
  TemplateKind,
} from '@/api/intendedConfig';
import { DEVICE_TYPES } from '@/lib/deviceTypes';

export const INTENDED_NAME_MAX = 100;
export const TEMPLATE_TEXT_MAX = 262144;
export const CONTEXT_DATA_MAX = 65536;
export const WEIGHT_MIN = 0;
export const WEIGHT_MAX = 100000;
export const DEFAULT_WEIGHT = 1000;

/** The scope a template or context starts with: any device. */
export const ANY_SCOPE: IntendedScope = { device_type: '', role_id: null, site_id: null, group_id: null };

export interface TemplateForm extends IntendedScope {
  name: string;
  kind: TemplateKind;
  template_text: string;
  description: string;
  enabled: boolean;
}

/** The template create / replace body: trimmed text fields, no scope on a snippet. */
export function templateBody(form: TemplateForm): ConfigTemplateInput {
  const scope = form.kind === 'snippet' ? ANY_SCOPE : pickScope(form);
  return {
    name: form.name.trim(),
    kind: form.kind,
    ...scope,
    template_text: form.template_text,
    description: form.description.trim(),
    enabled: form.enabled,
  };
}

export interface ContextForm extends IntendedScope {
  name: string;
  weight: number;
  description: string;
  enabled: boolean;
  host_id: number | null;
}

export function contextBody(form: ContextForm, data: Record<string, unknown>): ConfigContextInput {
  return {
    name: form.name.trim(),
    weight: form.weight,
    data,
    description: form.description.trim(),
    enabled: form.enabled,
    ...pickScope(form),
    host_id: form.host_id,
  };
}

function pickScope(scope: IntendedScope): IntendedScope {
  return { device_type: scope.device_type, role_id: scope.role_id, site_id: scope.site_id, group_id: scope.group_id };
}

/** The weight a field's text names, or null when it is not a whole number in range. */
export function parseWeight(text: string): number | null {
  const t = text.trim();
  if (!/^\d+$/.test(t)) return null;
  const n = Number(t);
  return n >= WEIGHT_MIN && n <= WEIGHT_MAX ? n : null;
}

/** A context's JSON text read as an object, or why it cannot be saved. */
export function parseContextData(text: string): { data: Record<string, unknown> } | { error: string } {
  if (text.length > CONTEXT_DATA_MAX) return { error: `Data must be ${CONTEXT_DATA_MAX.toLocaleString()} characters or fewer.` };
  if (!text.trim()) return { error: 'Data is required: a JSON object such as {"ntp_servers": ["192.0.2.10"]}.' };
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (err) {
    return { error: `Data is not valid JSON: ${(err as Error).message}` };
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return { error: 'Data must be a JSON object (in braces), not a list or a single value.' };
  }
  return { data: value as Record<string, unknown> };
}

/** "Line N: message" when the error names a line, else the message. */
export function lineMessage(message: string, line: number | null | undefined): string {
  return typeof line === 'number' ? `Line ${line}: ${message}` : message;
}

/** A failed template save that the template text caused (a 400 naming a line), worded for the field. */
export function templateTextError(err: unknown): string | null {
  if (err instanceof CustomDataError && err.status === 400 && err.line !== null) return lineMessage(err.message, err.line);
  return null;
}

/** A render error from the preview, naming the template when it is another one (an include). */
export function renderErrorText(error: RenderError, previewedName?: string | null): string {
  const text = lineMessage(error.message, error.line);
  // '(preview)' is the name the server renders unsaved text under.
  return error.template && error.template !== previewedName && error.template !== '(preview)'
    ? `${error.template}: ${text}`
    : text;
}

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n.toLocaleString()} ${n === 1 ? one : many}`;
}

/** The sentence after "Generate": what the run did. */
export function generateSummary(r: GenerateResult): string {
  const parts = [`${r.changed.toLocaleString()} changed`, plural(r.errors, 'error')];
  if (r.no_template) parts.push(`${plural(r.no_template, 'host')} without a template`);
  return `Generated ${r.generated.toLocaleString()} of ${plural(r.hosts, 'host')}: ${parts.join(', ')}.`;
}

/** Where an extra backup line sits: its parent lines, outermost first. */
export function extraParentText(path: readonly string[]): string {
  return path.length ? path.map((p) => p.trim()).join(' › ') : 'Top level';
}

/** The label of a driver key ('' when any). */
export function driverLabel(key: string): string {
  return DEVICE_TYPES.find((d) => d.value === key)?.label ?? key;
}

export interface NamedRecord {
  id: number;
  name: string;
}

/** The names of the scope records, by id; a list still loading is undefined. */
export interface ScopeNames {
  roles?: readonly NamedRecord[];
  sites?: readonly NamedRecord[];
  groups?: readonly NamedRecord[];
  hosts?: readonly NamedRecord[];
}

/** A scope record's name; "(deleted)" when the loaded list lacks it, "#id" while it loads. */
export function scopeName(list: readonly NamedRecord[] | undefined, id: number): string {
  if (!list) return `#${id}`;
  return list.find((r) => r.id === id)?.name ?? '(deleted)';
}

/** "Any device", or the set scope fields: "Driver Cisco IOS · Role core · Site (deleted)". */
export function scopeSummary(scope: IntendedScope & { host_id?: number | null }, names: ScopeNames): string {
  const parts: string[] = [];
  if (scope.device_type) parts.push(`Driver ${driverLabel(scope.device_type)}`);
  if (scope.role_id !== null) parts.push(`Role ${scopeName(names.roles, scope.role_id)}`);
  if (scope.site_id !== null) parts.push(`Site ${scopeName(names.sites, scope.site_id)}`);
  if (scope.group_id !== null) parts.push(`Group ${scopeName(names.groups, scope.group_id)}`);
  if (scope.host_id != null) parts.push(`Host ${scopeName(names.hosts, scope.host_id)}`);
  return parts.length ? parts.join(' · ') : 'Any device';
}

/**
 * The options of a scope select: the records, plus "(deleted)" for a chosen
 * id the loaded list lacks, so the select still shows what is stored.
 */
export function scopeOptions(list: readonly NamedRecord[] | undefined, current: number | null): NamedRecord[] {
  const options = [...(list ?? [])];
  if (list && current !== null && !list.some((r) => r.id === current)) options.push({ id: current, name: '(deleted)' });
  return options;
}

/** The driver options, plus the stored key when it is not a known driver. */
export function driverOptions(current: string): { value: string; label: string }[] {
  const options = [...DEVICE_TYPES];
  if (current && !options.some((d) => d.value === current)) options.push({ value: current, label: current });
  return options;
}

/** Every host of the group listing once, by hostname. */
export function hostsFromGroups(
  groups: readonly { hosts?: readonly { id: number; hostname: string; ip_address: string }[] }[] | undefined,
): { id: number; name: string; ip_address: string }[] {
  if (!groups) return [];
  const byId = new Map<number, { id: number; name: string; ip_address: string }>();
  for (const g of groups) {
    for (const h of g.hosts ?? []) if (!byId.has(h.id)) byId.set(h.id, { id: h.id, name: h.hostname, ip_address: h.ip_address });
  }
  return [...byId.values()].sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' }));
}

// ── Remediation ──────────────────────────────────────────────────────────────

/** Where the Deployments tab opens one deployment's detail. */
export function deploymentHref(id: number): string {
  return `/change-management/deployments?deployment=${id}`;
}

/** "3 commands: 2 added, 1 removed" plus the ignored lines, when any. */
export function remediationSummary(r: { commands: readonly string[]; added: number; removed: number; ignored: number }): string {
  const n = r.commands.length;
  const parts = [`${n.toLocaleString()} command${n === 1 ? '' : 's'}: ${r.added.toLocaleString()} added, ${r.removed.toLocaleString()} removed`];
  if (r.ignored) parts.push(`${r.ignored.toLocaleString()} line${r.ignored === 1 ? '' : 's'} ignored by rules`);
  return parts.join('; ');
}

/** The commands as text to copy, one per line, indentation kept. */
export function commandsText(commands: readonly string[]): string {
  return commands.length ? `${commands.join('\n')}\n` : '';
}

/** How a remediation ignore rule matches a line. */
export const IGNORE_KINDS: { value: 'exact' | 'prefix' | 'regex'; label: string; help: string }[] = [
  { value: 'exact', label: 'Exact line', help: 'The whole line, without its indentation' },
  { value: 'prefix', label: 'Starts with', help: 'Lines that start with the text' },
  { value: 'regex', label: 'Regular expression', help: 'RE2 syntax, case sensitive; no lookarounds or backreferences' },
];

export function ignoreKindLabel(kind: string): string {
  return IGNORE_KINDS.find((k) => k.value === kind)?.label ?? kind;
}
