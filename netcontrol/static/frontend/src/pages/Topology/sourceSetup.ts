/**
 * Pure helpers for the steps that follow adding a map source (Meraki, Cato,
 * FMC, Panorama, Appgate): check its credentials, run its first collection,
 * then optionally import the devices it found into the inventory with an
 * SNMP profile and a backup policy. The component (SourceSetupModal) only
 * renders what these return.
 */
import type {
  ImportableDevice,
  ImportDevicesRequest,
  ImportDevicesResult,
} from '@/api/sourceImport';

export type SetupStep = 'credentials' | 'collecting' | 'import';

/** The steps in order, with the label the step list shows. */
export const SETUP_STEPS: readonly { key: SetupStep; label: string }[] = [
  { key: 'credentials', label: 'Check credentials' },
  { key: 'collecting', label: 'First collection' },
  { key: 'import', label: 'Import devices' },
];

/** Where a step stands relative to the current one: shown as text, not only colour. */
export function stepState(step: SetupStep, current: SetupStep): 'done' | 'current' | 'todo' {
  const at = SETUP_STEPS.findIndex((s) => s.key === step);
  const now = SETUP_STEPS.findIndex((s) => s.key === current);
  if (at < now) return 'done';
  return at === now ? 'current' : 'todo';
}

/** The keys preselected for import: every device not in the inventory yet, up to `max`. */
export function defaultSelection(devices: readonly ImportableDevice[], max: number): Set<string> {
  return new Set(
    devices
      .filter((d) => !d.existing)
      .slice(0, Math.max(0, max))
      .map((d) => d.key),
  );
}

/**
 * `selected` with `key` toggled. A device already in the inventory is never
 * selected (the import would skip it), and nothing is added past `max`.
 */
export function toggleDevice(
  selected: ReadonlySet<string>,
  device: ImportableDevice,
  max: number,
): Set<string> {
  const next = new Set(selected);
  if (next.has(device.key)) next.delete(device.key);
  else if (!device.existing && next.size < max) next.add(device.key);
  return next;
}

/** Devices whose name, address, model, site or device type contains the query (case-insensitive). */
export function filterDevices(devices: readonly ImportableDevice[], query: string): ImportableDevice[] {
  const q = query.trim().toLowerCase();
  if (!q) return [...devices];
  return devices.filter((d) =>
    [d.name, d.ip, d.model, d.site, d.device_type].some((v) => v.toLowerCase().includes(q)),
  );
}

/** The profile preselected: the only one, or none when there are several (or none). */
export function soleProfileId(profiles: readonly { id: string }[] | undefined): string {
  return profiles && profiles.length === 1 ? profiles[0].id : '';
}

/** What Plexus does with a device once imported, in words: "Ping only", "Ping and SNMP"... */
export function capabilityText(device: Pick<ImportableDevice, 'capabilities'>): string {
  const parts = ['Ping'];
  if (device.capabilities.snmp_polling) parts.push('SNMP');
  if (device.capabilities.config_backup) parts.push('config backup');
  if (parts.length === 1) return 'Ping only';
  return `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}`;
}

/** How many of the selected devices Config Backups can read. */
export function backupCapableCount(
  devices: readonly ImportableDevice[],
  selected: ReadonlySet<string>,
): number {
  return devices.filter((d) => selected.has(d.key) && d.capabilities.config_backup).length;
}

/** How many of the selected devices are polled over SNMP once the group has a profile. */
export function snmpCapableCount(
  devices: readonly ImportableDevice[],
  selected: ReadonlySet<string>,
): number {
  return devices.filter((d) => selected.has(d.key) && d.capabilities.snmp_polling).length;
}

/** Where the devices go: a new top-level group by name, or an existing group. */
export type ImportTarget = { mode: 'new'; name: string } | { mode: 'existing'; groupId: number | null };

export interface ImportChoices {
  target: ImportTarget;
  /** '' for no profile. */
  profileId: string;
  /** null for no backup policy. */
  backupCredentialId: number | null;
}

/** Why the import cannot be sent yet, or null when it can. */
export function importBlocker(selectedCount: number, choices: ImportChoices): string | null {
  if (selectedCount === 0) return 'Select at least one device.';
  if (choices.target.mode === 'new' && !choices.target.name.trim()) return 'Name the new group.';
  if (choices.target.mode === 'existing' && choices.target.groupId == null) return 'Choose a group.';
  return null;
}

/** The request body for the selected devices, in list order. */
export function buildImportRequest(
  devices: readonly ImportableDevice[],
  selected: ReadonlySet<string>,
  choices: ImportChoices,
): ImportDevicesRequest {
  const body: ImportDevicesRequest = {
    device_keys: devices.filter((d) => selected.has(d.key)).map((d) => d.key),
  };
  if (choices.target.mode === 'new') body.new_group_name = choices.target.name.trim();
  else if (choices.target.groupId != null) body.group_id = choices.target.groupId;
  if (choices.profileId) body.snmp_profile_id = choices.profileId;
  if (choices.backupCredentialId != null) body.backup_credential_id = choices.backupCredentialId;
  return body;
}

function plural(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? '' : 's'}`;
}

/** What the import did, one sentence per line, for the result panel. */
export function describeImportResult(result: ImportDevicesResult): string[] {
  const lines = [
    `${plural(result.counts.added, 'device')} added to ${result.group.created ? 'the new group' : 'group'} "${result.group.name}".`,
  ];
  if (result.counts.skipped) lines.push(`${plural(result.counts.skipped, 'device')} already in the inventory, left as they are.`);
  if (result.counts.errors) lines.push(`${plural(result.counts.errors, 'device')} could not be added.`);
  const snmp = result.snmp_profile;
  if (snmp.status === 'assigned') lines.push(`SNMP profile "${snmp.profile_name}" assigned to the group.`);
  if (snmp.status === 'kept')
    lines.push(`The group already uses SNMP profile "${snmp.profile_name}"; it was kept.`);
  const backup = result.backup_policy;
  if (backup.status === 'created') {
    const every = backup.interval_seconds === 86400 ? 'daily' : `every ${Math.round((backup.interval_seconds ?? 0) / 3600)} h`;
    lines.push(`Backup policy "${backup.name}" created: ${every}, backups kept for ${backup.retention_days} days.`);
  }
  if (backup.status === 'exists') lines.push(`The group's backup policy "${backup.name}" now covers these devices too.`);
  if (!result.monitoring_enabled)
    lines.push('Monitoring is turned off: nothing is polled until it is turned on.');
  return lines;
}
