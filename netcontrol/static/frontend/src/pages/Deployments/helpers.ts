import type { Deployment, DeploymentStatus } from '@/api/deployments';
import type { ConfirmOptions } from '@/components/DialogProvider-context';

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

export function isApprovalBlocking(
  d: Pick<Deployment, 'requires_approval' | 'approval_status'>,
): boolean {
  return !!d.requires_approval && d.approval_status !== 'approved';
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

/** Confirmation shown before executing a deployment, from the list or the detail view. */
export function executeConfirmOptions(name: string): ConfirmOptions {
  return {
    title: 'Execute deployment',
    message: `Execute deployment "${name}"? Pre-deployment snapshots will be captured before pushing config changes.`,
    confirmLabel: 'Execute',
    confirmVariant: 'primary',
  };
}

/** Confirmation shown before rolling back a deployment, from the list or the detail view. */
export function rollbackConfirmOptions(name: string): ConfirmOptions {
  return {
    title: 'Roll back deployment',
    message: `Roll back deployment "${name}"? Pre-deployment config snapshots will be restored to all hosts.`,
    confirmLabel: 'Roll back',
  };
}
