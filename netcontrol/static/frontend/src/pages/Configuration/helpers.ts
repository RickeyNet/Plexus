import type {
  ConfigBackupPolicy,
  ConfigDriftEvent,
  RunBackupPolicyResult,
} from '@/api/configuration';

export type BackupView = 'config' | 'diff';

// A backup policy's credential choice in its form: a credential id,
// NO_CREDENTIAL (API-read devices only, such as OPNsense firewalls, which
// are backed up over their source's API key), or null (nothing chosen yet).
export const NO_CREDENTIAL = 'none';
export type PolicyCredentialChoice = number | typeof NO_CREDENTIAL | null;

// The choice a saved policy starts its edit form with.
export function policyCredentialChoice(
  policy: Pick<ConfigBackupPolicy, 'credential_id'> | null,
): PolicyCredentialChoice {
  if (policy == null) return null;
  return policy.credential_id ?? NO_CREDENTIAL;
}

// The credential_id a choice saves (null: no credential). Only for a made choice.
export function policyCredentialId(choice: number | typeof NO_CREDENTIAL): number | null {
  return choice === NO_CREDENTIAL ? null : choice;
}

// The note the policy list shows for a policy without a credential.
export function policyCredentialNote(
  policy: Pick<ConfigBackupPolicy, 'credential_id'>,
): string | null {
  return policy.credential_id == null ? 'No credential: API-read devices (OPNsense) only' : null;
}

// The failed hosts the Run Now message names; the others are under History.
const RUN_FAILURES_SHOWN = 5;

// What Run Now shows when it is done: the counts, then each failed host
// with its reason (the text of its error entry under History).
export function runBackupPolicyMessage(res: RunBackupPolicyResult): string {
  let msg = `Backup complete: ${res.backed_up} saved, ${res.errors} errors`;
  if (res.skipped) msg += `, ${res.skipped} unchanged (skipped)`;
  if (!res.errors) return msg;
  const lines = (res.failures ?? [])
    .slice(0, RUN_FAILURES_SHOWN)
    .map((f) => `${f.hostname || f.ip_address || `Host ${f.host_id}`}: ${f.error || 'no reason recorded'}`);
  const unnamed = res.errors - lines.length;
  if (unnamed > 0) {
    lines.push(`${unnamed}${lines.length ? ' more' : ''} failed: see their error entries under History.`);
  }
  return `${msg}\n\n${lines.join('\n')}`;
}

// Only successful captures have a config to diff. An unknown status (detail
// still loading) leaves the diff view available.
export function backupDiffAvailable(status: string | null | undefined): boolean {
  return status == null || status === 'success';
}

export function statusColor(status: string | null | undefined): string {
  if (status === 'open') return 'var(--danger)';
  if (status === 'accepted') return 'var(--warning)';
  return 'var(--success)';
}

export interface DriftGroup {
  diff_lines_added?: number;
  diff_lines_removed?: number;
  events: ConfigDriftEvent[];
  /** The event whose diff the group card shows. */
  representative_id: number;
}

// The server keys each listed event on its added and removed lines only
// (`diff_key`): the context lines of a unified diff carry per-host text, so
// the same change on several hosts shares a key.
export function groupDriftEvents(events: ConfigDriftEvent[]): DriftGroup[] {
  const groups = new Map<string, DriftGroup>();
  for (const ev of events) {
    const key = ev.diff_key ?? '';
    if (!groups.has(key)) {
      groups.set(key, {
        diff_lines_added: ev.diff_lines_added,
        diff_lines_removed: ev.diff_lines_removed,
        events: [],
        representative_id: ev.id,
      });
    }
    groups.get(key)!.events.push(ev);
  }
  return [...groups.values()].sort((a, b) => b.events.length - a.events.length);
}

export function filterDriftEvents(
  events: ConfigDriftEvent[],
  query: string,
): ConfigDriftEvent[] {
  const q = query.trim().toLowerCase();
  if (!q) return events;
  return events.filter(
    (e) =>
      (e.hostname || '').toLowerCase().includes(q) ||
      (e.ip_address || '').toLowerCase().includes(q) ||
      (e.device_type || '').toLowerCase().includes(q),
  );
}
