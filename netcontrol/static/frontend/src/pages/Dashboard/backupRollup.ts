import type { ConfigBackup } from '@/api/configuration';
import type { DeviceHealth } from '@/api/dashboard';

import { parseBackendDate } from './helpers';

// Pure backup-status roll-up shared by BackupStatusPanel and the dashboard's
// CriticalIssuesBanner. Kept out of the (lazy-loaded) panel module so the
// eagerly-rendered banner can reuse the classification without pulling the
// panel — and its deps — into the main bundle.

export type BackupState = 'success' | 'stale' | 'failed' | 'never';

export interface HostRollup {
  hostId: number;
  hostname: string;
  state: BackupState;
  capturedAt: string | null;
  errorMessage: string | null;
}

// A success that completed more than this many days ago is considered "stale".
// Most backup policies run daily-to-weekly; one week of silence is a clear
// signal something stopped running.
export const STALE_AFTER_DAYS = 7;

export function rollUpBackups(
  backups: ConfigBackup[],
  devices: DeviceHealth[],
): HostRollup[] {
  // Pick the most-recent backup row per host_id.
  const latestByHost = new Map<number, ConfigBackup>();
  for (const b of backups) {
    if (b.host_id == null) continue;
    const existing = latestByHost.get(b.host_id);
    if (!existing) {
      latestByHost.set(b.host_id, b);
      continue;
    }
    const t1 = parseBackendDate(b.captured_at)?.getTime() ?? 0;
    const t2 = parseBackendDate(existing.captured_at)?.getTime() ?? 0;
    if (t1 > t2) latestByHost.set(b.host_id, b);
  }

  const now = Date.now();
  const staleCutoff = now - STALE_AFTER_DAYS * 86400 * 1000;
  const rollups: HostRollup[] = [];

  // Hosts we have a backup row for.
  for (const b of latestByHost.values()) {
    if (b.host_id == null) continue;
    const ts = parseBackendDate(b.captured_at)?.getTime() ?? 0;
    let state: BackupState;
    if (b.status === 'failed') state = 'failed';
    else if (ts > 0 && ts < staleCutoff) state = 'stale';
    else state = 'success';
    rollups.push({
      hostId: b.host_id,
      hostname: b.hostname ?? b.ip_address ?? `Host ${b.host_id}`,
      state,
      capturedAt: b.captured_at ?? null,
      errorMessage: b.error_message ?? null,
    });
  }

  // Polled devices without any backup row → "never". We use device_health as
  // the inventory proxy since it's already in scope; hosts that aren't polled
  // and aren't backed up don't appear, which matches the rest of the
  // dashboard's "polled fleet" framing.
  const seen = new Set(rollups.map((r) => r.hostId));
  for (const d of devices) {
    if (d.host_id == null) continue;
    if (seen.has(d.host_id)) continue;
    rollups.push({
      hostId: d.host_id,
      hostname: d.hostname ?? d.ip_address ?? `Host ${d.host_id}`,
      state: 'never',
      capturedAt: null,
      errorMessage: null,
    });
  }

  // Problems first (failed → never → stale → success), then by hostname.
  const order: Record<BackupState, number> = { failed: 0, never: 1, stale: 2, success: 3 };
  rollups.sort((a, b) => {
    if (order[a.state] !== order[b.state]) return order[a.state] - order[b.state];
    return a.hostname.localeCompare(b.hostname);
  });
  return rollups;
}
