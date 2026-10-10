import type { SoftwareAdvisoryPayload } from '@/api/software';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export function severityBadgeClass(severity: string | null | undefined): string {
  switch ((severity ?? '').toLowerCase()) {
    case 'critical':
    case 'high':
      return 'badge badge-danger';
    case 'medium':
      return 'badge badge-warning';
    case 'low':
    case 'info':
      return 'badge badge-info';
    default:
      return 'badge badge-secondary';
  }
}

export function severityLabel(severity: string | null | undefined): string {
  const s = (severity ?? '').toLowerCase();
  if (!s) return '';
  return s === 'info' ? 'Info' : s.charAt(0).toUpperCase() + s.slice(1);
}

/** Lower index = more severe; unknown severities sort last. */
export function severityRank(severity: string | null | undefined): number {
  const index = SEVERITY_ORDER.indexOf((severity ?? '').toLowerCase());
  return index === -1 ? SEVERITY_ORDER.length : index;
}

export function sourceLabel(source: string | null | undefined): string {
  switch ((source ?? '').toLowerCase()) {
    case 'inventory':
      return 'Inventory';
    case 'meraki':
      return 'Meraki';
    case 'cato':
      return 'Cato';
    case 'fmc':
      return 'Cisco FMC';
    case 'panorama':
      return 'Palo Alto Panorama';
    case 'appgate':
      return 'Appgate SDP';
    case 'manual':
      return 'Manual';
    case 'import':
      return 'Imported';
    case 'cisco-psirt':
      return 'Cisco PSIRT';
    default:
      return source ?? '';
  }
}

export function formatTime(value: string | undefined | null): string {
  if (!value) return 'Never';
  const iso = value.includes('T') ? value : value.replace(' ', 'T');
  const withTz = /Z|[+-]\d\d:\d\d$/.test(iso) ? iso : `${iso}Z`;
  const d = new Date(withTz);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString();
}

/** One version specification per line or comma; blank entries dropped. */
export function parseVersionList(text: string): string[] {
  return text
    .split(/[\n;]+/)
    .map((line) => line.trim())
    .filter(Boolean);
}

export interface ParsedImport {
  advisories: SoftwareAdvisoryPayload[];
  error: string;
}

function asStringList(value: unknown): string[] {
  if (Array.isArray(value)) return value.map((v) => String(v).trim()).filter(Boolean);
  if (typeof value === 'string') return parseVersionList(value.replace(/,/g, '\n'));
  return [];
}

/**
 * Parse the JSON pasted into the import dialog: either a list of advisories
 * or `{ "advisories": [...] }`. Each entry needs an `advisory_id` and at least
 * one affected version; everything else is optional.
 */
export function parseAdvisoryImport(text: string): ParsedImport {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { advisories: [], error: 'Not valid JSON.' };
  }
  const list = Array.isArray(parsed)
    ? parsed
    : parsed && typeof parsed === 'object' && Array.isArray((parsed as { advisories?: unknown }).advisories)
      ? ((parsed as { advisories: unknown[] }).advisories)
      : null;
  if (!list) return { advisories: [], error: 'Expected a JSON list of advisories or {"advisories": [...]}.' };
  const advisories: SoftwareAdvisoryPayload[] = [];
  for (let i = 0; i < list.length; i += 1) {
    const raw = list[i];
    if (!raw || typeof raw !== 'object') return { advisories: [], error: `Entry ${i + 1} is not an object.` };
    const item = raw as Record<string, unknown>;
    const advisory_id = String(item.advisory_id ?? item.id ?? '').trim();
    if (!advisory_id) return { advisories: [], error: `Entry ${i + 1} has no advisory_id.` };
    const affected_versions = asStringList(item.affected_versions ?? item.affected);
    if (affected_versions.length === 0) {
      return { advisories: [], error: `Entry ${i + 1} (${advisory_id}) has no affected_versions.` };
    }
    const cvss = item.cvss == null || item.cvss === '' ? null : Number(item.cvss);
    advisories.push({
      advisory_id,
      title: String(item.title ?? '').trim(),
      severity: String(item.severity ?? 'medium').trim().toLowerCase(),
      cvss: cvss != null && Number.isFinite(cvss) ? cvss : null,
      platform: String(item.platform ?? '').trim().toLowerCase(),
      product_match: String(item.product_match ?? '').trim(),
      affected_versions,
      fixed_versions: asStringList(item.fixed_versions ?? item.fixed),
      cves: asStringList(item.cves),
      url: String(item.url ?? '').trim(),
      published: String(item.published ?? '').trim(),
      summary: String(item.summary ?? '').trim(),
      enabled: item.enabled == null ? true : Boolean(item.enabled),
    });
  }
  if (advisories.length === 0) return { advisories: [], error: 'The list is empty.' };
  return { advisories, error: '' };
}

/** Width (0-100) of a version's bar relative to the platform's biggest version. */
export function barWidth(count: number, max: number): number {
  if (max <= 0 || count <= 0) return 0;
  return Math.max(4, Math.round((count / max) * 100));
}

export type SoftwareTab = 'versions' | 'upgrades';

/**
 * Tab of the Software page a path opens: `/software/upgrades` opens Upgrades,
 * anything else Versions. (The upgrade tool's old path `/upgrades` is
 * redirected to `/software/upgrades` by the router.)
 */
export function softwareTabFromPath(pathname: string): SoftwareTab {
  return pathname === '/software/upgrades' ? 'upgrades' : 'versions';
}
