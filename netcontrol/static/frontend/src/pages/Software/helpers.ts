import type { SoftwareAdvisoryPayload } from '@/api/software';
import type { SoftwareEolEntryPayload, SoftwareEolState, SoftwareEolStatus } from '@/api/softwareEol';
import { isValidDate } from '@/lib/circuits';
import { formatDays } from '@/lib/lifecycle';
import type { Tone } from '@/lib/severity';

export function severityLabel(severity: string | null | undefined): string {
  const s = (severity ?? '').toLowerCase();
  if (!s) return '';
  return s === 'info' ? 'Info' : s.charAt(0).toUpperCase() + s.slice(1);
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
    case 'opnsense':
      return 'OPNsense';
    case 'manual':
      return 'Manual';
    case 'import':
      return 'Imported';
    case 'cisco-psirt':
      return 'Cisco PSIRT';
    case 'lifecycle':
      return 'End of life';
    default:
      return source ?? '';
  }
}

// ── CVE enrichment (NVD / CISA KEV) ─────────────────────────────────────────

interface KevFields {
  known_exploited?: boolean;
  kev_date_added?: string;
  kev_due_date?: string;
  kev_ransomware?: string;
}

/** Tooltip of the "Known exploited" marker; '' when the item is not known exploited. */
export function knownExploitedTitle(item: KevFields | null | undefined): string {
  if (!item?.known_exploited) return '';
  const parts = ['In the CISA Known Exploited Vulnerabilities catalogue'];
  if (item.kev_date_added) parts.push(`added ${item.kev_date_added}`);
  if (item.kev_due_date) parts.push(`remediation due ${item.kev_due_date}`);
  let text = parts.join(', ');
  if ((item.kev_ransomware ?? '').toLowerCase() === 'known') text += '; known to be used in ransomware campaigns';
  return `${text}.`;
}

/** Where an advisory's severity comes from, for its tooltip. */
export function severitySourceLabel(source: string | null | undefined, cvssSource?: string | null): string {
  switch ((source ?? '').toLowerCase()) {
    case 'admin':
      return 'Severity set by an administrator';
    case 'vendor':
      return "The vendor's severity rating";
    case 'enriched':
      return cvssSource === 'nvd'
        ? 'Severity from the NVD CVSS score and the CISA KEV catalogue'
        : 'Severity from the CVSS score and the CISA KEV catalogue';
    default:
      return 'Default severity (not set by a vendor, a CVSS score or an administrator)';
  }
}

/** The last enrichment run in one line: `completed: 12 CVE(s): …`; '' before the first run. */
export function cveRunSummary(status: string | null | undefined, message: string | null | undefined): string {
  if (!status) return '';
  return message ? `${status}: ${message}` : status;
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
    const severity = String(item.severity ?? '').trim().toLowerCase();
    advisories.push({
      advisory_id,
      title: String(item.title ?? '').trim(),
      // No severity: the server marks it a default one that CVE enrichment may set.
      ...(severity ? { severity } : {}),
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

export type SoftwareTab = 'versions' | 'upgrades' | 'lifecycle';

// ── Software end of life (release series; not the hardware lifecycle) ──────

/** The chip of a device's series status: `End of life since 2026-01-01 (estimate)`, `Ends in 23 days`; '' when unknown. */
export function softwareEolChip(status: SoftwareEolStatus | null | undefined): string {
  if (!status) return '';
  const estimate = status.estimate ? ' (estimate)' : '';
  switch (status.status) {
    case 'end_of_life':
      if (status.source === 'reported') {
        return status.successor ? `End of life (${status.successor} available)` : 'End of life (newer series available)';
      }
      return `End of life since ${status.date ?? '?'}${estimate}`;
    case 'ending':
      return `Ends ${formatDays(status.days)}${estimate}`;
    case 'supported':
      return `Supported until ${status.date ?? '?'}${estimate}`;
    default:
      return '';
  }
}

export function softwareEolTone(status: SoftwareEolStatus | null | undefined): Tone {
  switch (status?.status) {
    case 'end_of_life':
      return 'danger';
    case 'ending':
      return 'warning';
    case 'supported':
      return 'success';
    default:
      return 'neutral';
  }
}

/** The series statuses the device filter offers, in severity order. */
export const SOFTWARE_EOL_FILTERS: readonly { value: SoftwareEolState; label: string }[] = [
  { value: 'end_of_life', label: 'End of life' },
  { value: 'ending', label: 'Ending soon' },
  { value: 'supported', label: 'Supported' },
  { value: 'unknown', label: 'Unknown' },
];

/** Whether a device passes the series status filter ('' = every device). */
export function matchesSoftwareEolFilter(status: SoftwareEolStatus | null | undefined, filter: string): boolean {
  return !filter || (status?.status ?? 'unknown') === filter;
}

export interface SoftwareEolEntryErrors {
  platform?: string;
  series?: string;
  eol_date?: string;
  release_date?: string;
  url?: string;
}

/** The checks the server makes on an end-of-life entry, for the form (empty when valid). */
export function validateSoftwareEolEntry(input: SoftwareEolEntryPayload): SoftwareEolEntryErrors {
  const errors: SoftwareEolEntryErrors = {};
  if (!input.platform) errors.platform = 'Choose a platform.';
  const series = input.series.trim();
  if (!series) errors.series = 'A series is required, such as 25.1 or 17.9.';
  else if (!/^\d[A-Za-z0-9._()-]*$/.test(series)) errors.series = 'A series is a version such as 25.1 or 17.9.';
  if (!input.eol_date.trim()) errors.eol_date = 'The end-of-life date is required.';
  else if (!isValidDate(input.eol_date)) errors.eol_date = 'Use a real date as YYYY-MM-DD.';
  const release = (input.release_date ?? '').trim();
  if (release && !isValidDate(release)) errors.release_date = 'Use a real date as YYYY-MM-DD.';
  else if (release && !errors.eol_date && release > input.eol_date.trim()) {
    errors.release_date = 'The release date must not be after the end of life.';
  }
  const url = (input.url ?? '').trim();
  if (url && !/^https?:\/\//i.test(url)) errors.url = 'The URL must start with http:// or https://.';
  return errors;
}
