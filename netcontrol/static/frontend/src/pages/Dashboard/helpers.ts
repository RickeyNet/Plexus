import type { DeviceHealth } from '@/api/dashboard';
import { parseBackendDate } from '@/lib/datetime';

// Re-exported for existing importers; canonical impl lives in @/lib/datetime.
export { parseBackendDate };

export type HealthStatus = 'healthy' | 'warning' | 'critical' | 'down' | 'unknown';

export function classifyDeviceHealth(poll: DeviceHealth | undefined | null): HealthStatus {
  if (!poll) return 'unknown';
  if (poll.poll_status === 'error') return 'down';
  const { cpu_percent: cpu, memory_percent: mem, packet_loss_pct: pktLoss } = poll;
  if (
    (cpu != null && cpu >= 90) ||
    (mem != null && mem >= 95) ||
    (pktLoss != null && pktLoss >= 50)
  ) {
    return 'critical';
  }
  if (
    (cpu != null && cpu >= 75) ||
    (mem != null && mem >= 80) ||
    (pktLoss != null && pktLoss >= 10) ||
    (poll.if_down_count ?? 0) > 0
  ) {
    return 'warning';
  }
  if (cpu != null || mem != null) return 'healthy';
  return 'unknown';
}

export type SortBy = 'severity' | 'name' | 'cpu' | 'memory';

const SEVERITY_ORDER: Record<HealthStatus, number> = {
  down: 0,
  critical: 1,
  warning: 2,
  unknown: 3,
  healthy: 4,
};

export function sortDevices(devices: DeviceHealth[], sortBy: SortBy): DeviceHealth[] {
  const copy = [...devices];
  switch (sortBy) {
    case 'severity':
      return copy.sort((a, b) => SEVERITY_ORDER[classifyDeviceHealth(a)] - SEVERITY_ORDER[classifyDeviceHealth(b)]);
    case 'name':
      return copy.sort((a, b) => (a.hostname ?? '').localeCompare(b.hostname ?? ''));
    case 'cpu':
      return copy.sort((a, b) => (b.cpu_percent ?? -1) - (a.cpu_percent ?? -1));
    case 'memory':
      return copy.sort((a, b) => (b.memory_percent ?? -1) - (a.memory_percent ?? -1));
    default:
      return copy;
  }
}

export function formatUptime(seconds: number | null | undefined): string {
  if (seconds == null) return '-';
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  if (days > 0) return `${days}d ${hours}h`;
  const mins = Math.floor((seconds % 3600) / 60);
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

export function timeAgo(isoStr: string | null | undefined): string {
  if (!isoStr) return '-';
  const date = parseBackendDate(isoStr);
  if (!date) return isoStr;
  const diff = (Date.now() - date.getTime()) / 1000;
  if (diff < 60) return 'just now';
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}
