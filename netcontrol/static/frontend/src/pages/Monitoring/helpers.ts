export function formatTimestamp(ts: string | null | undefined): string {
  if (!ts) return '-';
  return new Date(ts + (ts.endsWith('Z') ? '' : 'Z')).toLocaleString();
}

export function formatUptime(seconds: number | null | undefined): string {
  if (seconds == null) return 'N/A';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

export function formatMinutes(min: number | null | undefined): string {
  if (min == null) return '-';
  if (min < 60) return `${min.toFixed(1)}m`;
  const h = Math.floor(min / 60);
  const m = Math.round(min % 60);
  return `${h}h ${m}m`;
}

export const SEVERITY_COLOR: Record<string, string> = {
  critical: 'danger',
  warning: 'warning',
  info: 'primary',
};

export function severityColor(sev: string | undefined | null): string {
  if (!sev) return 'text-muted';
  return SEVERITY_COLOR[sev] ?? 'text-muted';
}

export interface SlaCompliance {
  status: 'met' | 'warn' | 'breach' | 'none';
}

export function getHostSlaCompliance(
  host: { uptime_pct?: number | null; avg_latency_ms?: number | null; jitter_ms?: number | null; avg_packet_loss_pct?: number | null; host_id: number },
  targets: { metric: string; target_value: number; warning_value: number; enabled: boolean; host_id?: number | null; group_id?: number | null }[],
): SlaCompliance {
  const applicable = targets.filter((t) => t.enabled && (t.host_id == null || t.host_id === host.host_id));
  if (!applicable.length) return { status: 'none' };

  let worst: 'met' | 'warn' | 'breach' = 'met';
  for (const t of applicable) {
    const value = t.metric === 'uptime' ? host.uptime_pct
      : t.metric === 'latency' ? host.avg_latency_ms
      : t.metric === 'jitter' ? host.jitter_ms
      : t.metric === 'packet_loss' ? host.avg_packet_loss_pct
      : null;
    if (value == null) continue;
    const higherIsBetter = t.metric === 'uptime';
    let status: 'met' | 'warn' | 'breach';
    if (higherIsBetter) {
      if (value >= t.target_value) status = 'met';
      else if (value >= t.warning_value) status = 'warn';
      else status = 'breach';
    } else {
      if (value <= t.target_value) status = 'met';
      else if (value <= t.warning_value) status = 'warn';
      else status = 'breach';
    }
    if (status === 'breach') worst = 'breach';
    else if (status === 'warn' && worst === 'met') worst = 'warn';
  }
  return { status: worst };
}
