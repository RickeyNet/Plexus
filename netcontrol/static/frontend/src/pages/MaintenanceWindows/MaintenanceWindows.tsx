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
import { PageHelp } from '@/components/PageHelp';

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

function formatStamp(iso?: string | null): string {
  if (!iso) return '-';
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function describeScope(w: MaintenanceWindow): string {
  if (!w.scopes || w.scopes.length === 0) return 'All groups (global)';
  return w.scopes.map((s) => s.group_name || `#${s.group_id}`).join(', ');
}

export function MaintenanceWindows() {
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

  const handleDelete = (w: MaintenanceWindow) => {
    if (!confirm(`Delete maintenance window "${w.name}"?`)) return;
    deleteMut.mutate(w.id, {
      onError: (e) => alert((e as Error).message),
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
          gap: '0.5rem',
          marginBottom: '0.75rem',
        }}
      >
        <h2 style={{ margin: 0 }}>Maintenance Windows</h2>
        <button
          type="button"
          className="btn btn-primary btn-sm"
          onClick={() => setShowCreate(true)}
        >
          New Window
        </button>
      </div>

      {windows.isPending && <p className="text-muted">Loading…</p>}
      {windows.error && (
        <p style={{ color: 'var(--danger)' }}>
          Failed to load: {(windows.error as Error).message}
        </p>
      )}

      {sorted.length === 0 && !windows.isPending && (
        <p className="text-muted">
          No maintenance windows defined. Changes will proceed without time
          restrictions; the approval gate still applies for production
          groups and high-risk changes.
        </p>
      )}

      {sorted.length > 0 && (
        <table style={{ width: '100%', fontSize: '0.88em', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ textAlign: 'left', borderBottom: '1px solid var(--border)' }}>
              <th style={{ padding: '6px 8px' }}>Name</th>
              <th style={{ padding: '6px 8px' }}>Window</th>
              <th style={{ padding: '6px 8px' }}>Recurrence</th>
              <th style={{ padding: '6px 8px' }}>Scope</th>
              <th style={{ padding: '6px 8px' }}>Policy</th>
              <th style={{ padding: '6px 8px' }}>State</th>
              <th style={{ padding: '6px 8px' }}></th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((w) => (
              <tr key={w.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                <td style={{ padding: '6px 8px' }}>
                  <strong>{w.name}</strong>
                  {w.description && (
                    <div style={{ color: 'var(--text-muted)', fontSize: '0.85em' }}>
                      {w.description}
                    </div>
                  )}
                </td>
                <td style={{ padding: '6px 8px', fontSize: '0.85em' }}>
                  <div>{formatStamp(w.start_at)}</div>
                  <div style={{ color: 'var(--text-muted)' }}>
                    → {formatStamp(w.end_at)}
                  </div>
                </td>
                <td style={{ padding: '6px 8px' }}>
                  {RECURRENCE_LABEL[w.recurrence] || w.recurrence}
                  {w.recurrence === 'weekly' && w.weekday_mask > 0 && (
                    <div style={{ color: 'var(--text-muted)', fontSize: '0.85em' }}>
                      {formatWeekdayMask(w.weekday_mask)}
                    </div>
                  )}
                </td>
                <td style={{ padding: '6px 8px', fontSize: '0.85em' }}>{describeScope(w)}</td>
                <td style={{ padding: '6px 8px' }}>
                  <span
                    style={{
                      color: `var(--${policyColor(w.policy)})`,
                      fontWeight: 600,
                    }}
                  >
                    {POLICY_LABEL[w.policy] || w.policy}
                  </span>
                </td>
                <td style={{ padding: '6px 8px' }}>
                  {!w.enabled ? (
                    <span style={{ color: 'var(--text-muted)' }}>disabled</span>
                  ) : w.is_active ? (
                    <span style={{ color: 'var(--success)', fontWeight: 600 }}>active</span>
                  ) : (
                    <span style={{ color: 'var(--text-muted)' }}>idle</span>
                  )}
                </td>
                <td style={{ padding: '6px 8px', textAlign: 'right' }}>
                  <button
                    type="button"
                    className="btn btn-ghost btn-sm"
                    onClick={() => setEditingId(w.id)}
                  >
                    Edit
                  </button>
                  <button
                    type="button"
                    className="btn btn-ghost btn-sm"
                    style={{ color: 'var(--danger)' }}
                    disabled={deleteMut.isPending}
                    onClick={() => handleDelete(w)}
                  >
                    Delete
                  </button>
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
