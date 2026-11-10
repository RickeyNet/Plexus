import { useMemo, useState } from 'react';

import { useInventoryGroupsFull } from '@/api/inventory';
import {
  type MaintenanceWindow,
  type WindowPolicy,
  type WindowRecurrence,
  formatWeekdayMask,
  useDeleteMaintenanceWindow,
  useMaintenanceWindows,
} from '@/api/maintenanceWindows';
import { Callout } from '@/components/Callout';
import { DeleteButton } from '@/components/DeleteButton';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { PageHelp } from '@/components/PageHelp';
import { useDialogs } from '@/components/DialogProvider-context';
import { formatBackendDateTime } from '@/lib/datetime';

import { MaintenanceWindowModal } from './MaintenanceWindowModal';

const POLICY_LABEL: Record<WindowPolicy, string> = {
  allow_changes: 'Allow inside',
  block_outside_window: 'Block outside',
  warn_outside_window: 'Warn outside',
};

const RECURRENCE_LABEL: Record<WindowRecurrence, string> = {
  none: 'One-shot',
  daily: 'Daily',
  weekly: 'Weekly',
};

function policyColor(policy: WindowPolicy): string {
  if (policy === 'block_outside_window') return 'danger';
  if (policy === 'warn_outside_window') return 'warning';
  return 'success';
}

function describeScope(w: MaintenanceWindow): string {
  if (!w.scopes || w.scopes.length === 0) return 'All groups (global)';
  return w.scopes.map((s) => s.group_name || `#${s.group_id}`).join(', ');
}

export function MaintenanceWindows() {
  const { confirm, alert } = useDialogs();
  const windows = useMaintenanceWindows();
  const groups = useInventoryGroupsFull(false);
  const deleteMut = useDeleteMaintenanceWindow();
  const [editingId, setEditingId] = useState<number | null>(null);
  const [showCreate, setShowCreate] = useState(false);

  const sorted = useMemo(() => {
    const rows = windows.data || [];
    return [...rows].sort((a, b) => {
      // Active first, then upcoming start, then name.
      if (!!a.is_active !== !!b.is_active) return a.is_active ? -1 : 1;
      return (a.start_at || '').localeCompare(b.start_at || '');
    });
  }, [windows.data]);

  const handleDelete = async (w: MaintenanceWindow) => {
    if (!(await confirm({
      title: 'Delete maintenance window',
      message: `Delete maintenance window "${w.name}"?`,
      confirmLabel: 'Delete',
    }))) return;
    deleteMut.mutate(w.id, {
      onError: (e) => void alert({ message: (e as Error).message, variant: 'error' }),
    });
  };

  return (
    <div>
      <PageHelp
        pageKey="change-management.maintenance"
        title="Maintenance Windows"
        text="Define when production changes are allowed. Windows scoped to inventory groups gate deployments targeting those groups; global windows apply everywhere. Policy controls whether changes outside the window are blocked or just warned."
      />

      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 'var(--space-2)',
          marginBottom: 'var(--space-3)',
        }}
      >
        <h3 style={{ margin: 0 }}>Maintenance Windows</h3>
        <button
          type="button"
          className="btn btn-primary btn-sm"
          onClick={() => setShowCreate(true)}
        >
          New Window
        </button>
      </div>

      {windows.isPending && <LoadingState />}
      {windows.error && (
        <Callout tone="danger">
          Failed to load: {(windows.error as Error).message}
        </Callout>
      )}

      {sorted.length === 0 && !windows.isPending && (
        <EmptyState compact message="No maintenance windows defined. Changes will proceed without time
          restrictions; the approval gate still applies for production
          groups and high-risk changes." />
      )}

      {sorted.length > 0 && (
        <table className="data-table table-sm">
          <thead>
            <tr>
              <th>Name</th>
              <th>Window</th>
              <th>Recurrence</th>
              <th>Scope</th>
              <th>Policy</th>
              <th>State</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((w) => (
              <tr key={w.id}>
                <td>
                  <strong>{w.name}</strong>
                  {w.description && (
                    <div style={{ color: 'var(--text-muted)', fontSize: '0.85em' }}>
                      {w.description}
                    </div>
                  )}
                </td>
                <td style={{ fontSize: '0.85em' }}>
                  <div>{formatBackendDateTime(w.start_at)}</div>
                  <div style={{ color: 'var(--text-muted)' }}>
                    → {formatBackendDateTime(w.end_at)}
                  </div>
                </td>
                <td>
                  {RECURRENCE_LABEL[w.recurrence] || w.recurrence}
                  {w.recurrence === 'weekly' && w.weekday_mask > 0 && (
                    <div style={{ color: 'var(--text-muted)', fontSize: '0.85em' }}>
                      {formatWeekdayMask(w.weekday_mask)}
                    </div>
                  )}
                </td>
                <td style={{ fontSize: '0.85em' }}>{describeScope(w)}</td>
                <td>
                  <span
                    style={{
                      color: `var(--${policyColor(w.policy)})`,
                      fontWeight: 600,
                    }}
                  >
                    {POLICY_LABEL[w.policy] || w.policy}
                  </span>
                </td>
                <td>
                  {!w.enabled ? (
                    <span style={{ color: 'var(--text-muted)' }}>disabled</span>
                  ) : w.is_active ? (
                    <span style={{ color: 'var(--success)', fontWeight: 600 }}>active</span>
                  ) : (
                    <span style={{ color: 'var(--text-muted)' }}>idle</span>
                  )}
                </td>
                <td style={{ textAlign: 'right' }}>
                  <button
                    type="button"
                    className="btn btn-ghost btn-sm"
                    onClick={() => setEditingId(w.id)}
                  >
                    Edit
                  </button>
                  <DeleteButton disabled={deleteMut.isPending} onClick={() => handleDelete(w)} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <MaintenanceWindowModal
        isOpen={showCreate}
        onClose={() => setShowCreate(false)}
        groups={groups.data || []}
      />
      <MaintenanceWindowModal
        isOpen={editingId != null}
        onClose={() => setEditingId(null)}
        editingId={editingId}
        groups={groups.data || []}
      />
    </div>
  );
}
