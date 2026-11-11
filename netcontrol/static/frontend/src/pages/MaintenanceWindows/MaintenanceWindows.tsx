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
import { Badge } from '@/components/Badge';
import { DeleteButton } from '@/components/DeleteButton';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { PageHelp } from '@/components/PageHelp';
import { QueryError } from '@/components/QueryError';
import { useDialogs } from '@/components/DialogProvider-context';
import { formatBackendDateTime } from '@/lib/datetime';
import type { Tone } from '@/lib/severity';

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

function policyTone(policy: WindowPolicy): Tone {
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

      {/* No heading here: the active tab and the help banner already name the section. */}
      <div className="toolbar">
        <span className="toolbar-spacer" />
        <button type="button" className="btn btn-primary" onClick={() => setShowCreate(true)}>
          + New Window
        </button>
      </div>

      {windows.error && !windows.data ? (
        <QueryError what="maintenance windows" query={windows} />
      ) : (
        windows.isPending && <LoadingState />
      )}

      {windows.data && sorted.length === 0 && (
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
                  <Badge tone={policyTone(w.policy)} size="sm">
                    {POLICY_LABEL[w.policy] || w.policy}
                  </Badge>
                </td>
                <td>
                  {!w.enabled ? (
                    <Badge size="sm">Disabled</Badge>
                  ) : w.is_active ? (
                    <Badge tone="success" size="sm">Active</Badge>
                  ) : (
                    <Badge size="sm">Idle</Badge>
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
        isOpen={showCreate || editingId != null}
        onClose={() => {
          setShowCreate(false);
          setEditingId(null);
        }}
        editingId={editingId}
        groups={groups.data || []}
      />
    </div>
  );
}
