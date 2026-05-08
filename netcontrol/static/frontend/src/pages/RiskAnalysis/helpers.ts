import type { RiskAnalysis, RiskLevel } from '@/api/riskAnalysis';

export const LEVEL_COLORS: Record<string, string> = {
  low: 'success',
  medium: 'warning',
  high: 'warning',
  critical: 'danger',
  unknown: 'text-muted',
};

export function levelColor(level: string | undefined): string {
  if (!level) return 'text-muted';
  return LEVEL_COLORS[level] || 'text-muted';
}

export function scorePercent(score: number | undefined): number {
  return Math.round((score || 0) * 100);
}

export function formatStamp(iso: string | null | undefined): string {
  if (!iso) return '-';
  return new Date(iso + 'Z').toLocaleString();
}

export function parseJsonArray<T = unknown>(raw: string | null | undefined): T[] {
  if (!raw) return [];
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? (v as T[]) : [];
  } catch {
    return [];
  }
}

export function parseJsonObject<T = Record<string, unknown>>(raw: string | null | undefined): T {
  if (!raw) return {} as T;
  try {
    const v = JSON.parse(raw);
    return v && typeof v === 'object' ? (v as T) : ({} as T);
  } catch {
    return {} as T;
  }
}

export function targetLabel(a: RiskAnalysis): string {
  if (a.hostname) return `${a.hostname}${a.ip_address ? ` (${a.ip_address})` : ''}`;
  if (a.group_name) return `Group: ${a.group_name}`;
  return 'N/A';
}

export interface RiskFilter {
  query: string;
  level: '' | RiskLevel | string;
}

export function filterAnalyses(items: RiskAnalysis[], f: RiskFilter): RiskAnalysis[] {
  const q = f.query.toLowerCase();
  return items.filter((a) => {
    if (f.level && a.risk_level !== f.level) return false;
    if (!q) return true;
    return (
      (a.hostname || '').toLowerCase().includes(q) ||
      (a.group_name || '').toLowerCase().includes(q) ||
      (a.change_type || '').toLowerCase().includes(q)
    );
  });
}
