/** Shared formatting helpers for the Device Detail page. Mirrors legacy app.js. */

export function formatUptime(seconds: number | null | undefined): string {
  if (!seconds) return 'N/A';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

export function formatRate(bps: number | null | undefined): string {
  if (bps == null) return '-';
  if (bps >= 1e9) return (bps / 1e9).toFixed(2) + ' Gbps';
  if (bps >= 1e6) return (bps / 1e6).toFixed(2) + ' Mbps';
  if (bps >= 1e3) return (bps / 1e3).toFixed(1) + ' Kbps';
  return Math.round(bps) + ' bps';
}

export function formatSpeed(mbps: number | null | undefined): string {
  if (!mbps) return '-';
  return mbps >= 1000 ? mbps / 1000 + ' Gbps' : mbps + ' Mbps';
}

/** Convert a relative range string ("24h", "7d", etc.) to milliseconds. */
export function rangeToMs(range: string): number {
  const m = /^(\d+)([smhdw])$/.exec(range);
  if (!m) return 24 * 3600 * 1000;
  const n = parseInt(m[1], 10);
  const unit = m[2];
  const map: Record<string, number> = {
    s: 1000,
    m: 60_000,
    h: 3_600_000,
    d: 86_400_000,
    w: 604_800_000,
  };
  return n * (map[unit] || 3_600_000);
}

export const isVlan = (n: string) =>
  /^(Vl|Vlan|vlan|BDI|irb\.|vlan\.)\s*[\d]/i.test(n) || /vlan/i.test(n);
export const isLoopback = (n: string) => /^(Lo|Loopback|lo[\d])/i.test(n);
export const isMgmt = (n: string) =>
  /^(Mgmt|Management|mgmt|ma[\d]|FastEthernet0$|GigabitEthernet0$)/i.test(n) ||
  /^(Null|Embedded-Service|NV|Async|Voice|Cellular)/i.test(n);
export const isPortChannel = (n: string) =>
  /^(Po|Port-channel|port-channel|ae[\d]|Bundle-Ether)/i.test(n);
export const isTunnel = (n: string) => /^(Tu|Tunnel|tunnel[\d])/i.test(n);
