import type { ComplianceProfile } from '@/api/compliance';

/** Display label of a Meraki compliance target kind. */
export const MERAKI_KIND_LABEL: Record<string, string> = {
  org: 'Organization',
  network: 'Network',
  device: 'Switch',
  ssid: 'SSID',
};

/** CSS colour token for a scan status. */
export function statusColor(status: string): string {
  if (status === 'compliant') return 'success';
  if (status === 'error') return 'warning';
  return 'danger';
}

/** True when a profile carries at least one rule of type "meraki". */
export function profileHasMerakiRules(profile: ComplianceProfile): boolean {
  try {
    const rules = JSON.parse(profile.rules || '[]') as { type?: string }[];
    return Array.isArray(rules) && rules.some((r) => (r?.type || '').toLowerCase() === 'meraki');
  } catch {
    return false;
  }
}
