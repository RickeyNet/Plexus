import type { Deployment, DeploymentStatus } from '@/api/deployments';

export const STATUS_COLORS: Record<string, string> = {
  planning: 'text-muted',
  'pre-check': 'warning',
  executing: 'warning',
  'post-check': 'warning',
  completed: 'success',
  failed: 'danger',
  'rolled-back': 'warning',
  'rolling-back': 'warning',
  verifying: 'warning',
  verified: 'success',
  verification_failed: 'danger',
};

export function statusColor(status: DeploymentStatus | string | undefined): string {
  return STATUS_COLORS[status || ''] || 'text-muted';
}

export function rollbackStatusColor(status: string | null | undefined): string {
  if (status === 'completed') return 'success';
  if (status === 'failed') return 'danger';
  return 'warning';
}

export function formatStamp(iso: string | null | undefined): string {
  if (!iso) return '';
  const hasZone = iso.includes('Z') || iso.includes('+');
  return new Date(iso + (hasZone ? '' : 'Z')).toLocaleString();
}

export function formatTime(iso: string | null | undefined): string {
  if (!iso) return '';
  const hasZone = iso.includes('Z') || iso.includes('+');
  return new Date(iso + (hasZone ? '' : 'Z')).toLocaleTimeString();
}

export function commandCount(commands: string | null | undefined): number {
  if (!commands) return 0;
  return commands.split('\n').filter((l) => l.trim()).length;
}

export function filterDeployments(
  items: Deployment[],
  { query, status }: { query: string; status: string },
): Deployment[] {
  const q = query.trim().toLowerCase();
  return items.filter((d) => {
    if (status && d.status !== status) return false;
    if (!q) return true;
    return (
      (d.name || '').toLowerCase().includes(q) ||
      (d.group_name || '').toLowerCase().includes(q) ||
      (d.description || '').toLowerCase().includes(q)
    );
  });
}

export function canExecute(status: DeploymentStatus | string): boolean {
  return status === 'planning' || status === 'failed';
}

export function canRollback(status: DeploymentStatus | string): boolean {
  return (
    status === 'completed' ||
    status === 'failed' ||
    status === 'verified' ||
    status === 'verification_failed'
  );
}

export function canDelete(status: DeploymentStatus | string): boolean {
  return ['planning', 'completed', 'failed', 'rolled-back'].includes(status);
}
