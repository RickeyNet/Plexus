import { useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';

import {
  type DashboardPanel,
  type DashboardVariable,
  type InventoryGroupWithHosts,
  useCustomDashboard,
  useDeleteCustomDashboard,
  useDeletePanel,
  useInventoryGroupsForDashboard,
} from '@/api/dashboard';
import { useDialogs } from '@/components/DialogProvider-context';

import { Panel } from './Panel';
import { PanelModal } from './PanelModal';

function parseVariables(json: string | undefined): DashboardVariable[] {
  if (!json) return [];
  try {
    const parsed = JSON.parse(json);
    return Array.isArray(parsed) ? (parsed as DashboardVariable[]) : [];
  } catch {
    return [];
  }
}

export function DashboardViewer() {
  const { confirm, alert } = useDialogs();
  const { id } = useParams<{ id: string }>();
  const dashboardId =
    id != null && Number.isFinite(Number(id)) ? Number(id) : null;
  const navigate = useNavigate();

  const dashQuery = useCustomDashboard(dashboardId);
  const deleteDashboard = useDeleteCustomDashboard();
  const deletePanel = useDeletePanel(dashboardId ?? 0);

  const [editing, setEditing] = useState(false);
  const [showAddPanel, setShowAddPanel] = useState(false);
  const [editPanel, setEditPanel] = useState<DashboardPanel | null>(null);
  const [variableValues, setVariableValues] = useState<Record<string, string>>({});

  const variables = useMemo(
    () => parseVariables(dashQuery.data?.variables_json),
    [dashQuery.data?.variables_json],
  );
  const needsHosts = variables.some((v) => v.type === 'host');
  const groupsQuery = useInventoryGroupsForDashboard(needsHosts || variables.some((v) => v.type === 'group'));

  if (dashQuery.isPending) {
    return (
      <>
        <div className="page-header">
          <h2>Dashboard</h2>
        </div>
        <div className="skeleton skeleton-card" style={{ height: 200 }} />
      </>
    );
  }

  if (dashQuery.error || !dashQuery.data) {
    return (
      <>
        <div className="page-header">
          <h2>Dashboard</h2>
        </div>
        <div className="glass-card card" style={{ borderColor: 'var(--danger)' }}>
          <strong>Failed to load dashboard:</strong>{' '}
          {dashQuery.error ? (dashQuery.error as Error).message : 'Not found'}
        </div>
        <div style={{ marginTop: '1rem' }}>
          <Link to="/dashboards" className="btn btn-secondary">
            ← Back to Dashboards
          </Link>
        </div>
      </>
    );
  }

  const dashboard = dashQuery.data;
  const panels = dashboard.panels ?? [];

  const handleDeleteDashboard = async () => {
    if (!dashboardId) return;
    if (!(await confirm('Delete this dashboard? All panels will be removed. This action cannot be undone.'))) return;
    deleteDashboard.mutate(dashboardId, {
      onSuccess: () => navigate('/dashboards'),
      onError: (e) => {
        void alert({ message: (e as Error).message, variant: 'error' });
      },
    });
  };

  const handleDeletePanel = async (panel: DashboardPanel) => {
    if (!(await confirm('Delete this panel?'))) return;
    deletePanel.mutate(panel.id, {
      onError: (e) => {
        void alert({ message: (e as Error).message, variant: 'error' });
      },
    });
  };

  return (
    <>
      <div
        className="page-header"
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '0.5rem',
          marginBottom: '0.75rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <Link to="/dashboards" className="btn btn-sm btn-secondary">
            ← Back
          </Link>
          <h2 style={{ margin: 0, fontSize: '1.25rem' }}>{dashboard.name}</h2>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
          <VariablesBar
            variables={variables}
            values={variableValues}
            onChange={setVariableValues}
            groups={groupsQuery.data ?? []}
          />
          <button
            className={editing ? 'btn btn-primary' : 'btn btn-secondary'}
            onClick={() => setEditing((v) => !v)}
          >
            {editing ? 'Done' : 'Edit'}
          </button>
          <button
            className="btn btn-secondary"
            onClick={() => dashQuery.refetch()}
          >
            Refresh
          </button>
          {editing && (
            <button className="btn btn-danger btn-sm" onClick={handleDeleteDashboard}>
              Delete
            </button>
          )}
        </div>
      </div>

      {panels.length === 0 ? (
        <div className="empty-state" style={{ padding: '3rem 1rem' }}>
          <svg
            width="64"
            height="64"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={1}
            strokeLinecap="round"
            strokeLinejoin="round"
            style={{ opacity: 0.3 }}
          >
            <rect x="3" y="3" width="18" height="18" rx="2" ry="2" />
            <line x1="3" y1="9" x2="21" y2="9" />
            <line x1="9" y1="21" x2="9" y2="9" />
          </svg>
          <h3>No Panels Yet</h3>
          <p style={{ color: 'var(--text-muted)', marginBottom: '1rem' }}>
            Click <strong>Edit</strong> then <strong>+ Add Panel</strong> to get started.
          </p>
        </div>
      ) : (
        <div className="dashboard-grid">
          {panels.map((p) => (
            <Panel
              key={p.id}
              panel={p}
              variables={variableValues}
              range="6h"
              editing={editing}
              onEdit={(panel) => setEditPanel(panel)}
              onDelete={handleDeletePanel}
            />
          ))}
        </div>
      )}

      {editing && (
        <div style={{ marginTop: '1rem' }}>
          <button className="btn btn-primary" onClick={() => setShowAddPanel(true)}>
            + Add Panel
          </button>
        </div>
      )}

      {dashboardId != null && (
        <>
          <PanelModal
            isOpen={showAddPanel}
            onClose={() => setShowAddPanel(false)}
            dashboardId={dashboardId}
          />
          <PanelModal
            isOpen={editPanel != null}
            onClose={() => setEditPanel(null)}
            dashboardId={dashboardId}
            panel={editPanel}
          />
        </>
      )}
    </>
  );
}

interface VariablesBarProps {
  variables: DashboardVariable[];
  values: Record<string, string>;
  onChange: (values: Record<string, string>) => void;
  groups: InventoryGroupWithHosts[];
}

function VariablesBar({ variables, values, onChange, groups }: VariablesBarProps) {
  if (!variables.length) return null;

  return (
    <div className="dashboard-variables" style={{ display: 'flex', gap: '0.5rem' }}>
      {variables.map((v) => {
        const value = values[v.name] ?? '*';
        const set = (next: string) => onChange({ ...values, [v.name]: next });

        if (v.type === 'group') {
          return (
            <select
              key={v.name}
              className="form-select form-select-sm"
              value={value}
              onChange={(e) => set(e.target.value)}
            >
              <option value="*">All Groups</option>
              {groups.map((g) => (
                <option key={g.id} value={String(g.id)}>
                  {g.name}
                </option>
              ))}
            </select>
          );
        }
        if (v.type === 'host') {
          return (
            <select
              key={v.name}
              className="form-select form-select-sm"
              value={value}
              onChange={(e) => set(e.target.value)}
            >
              <option value="*">All Hosts</option>
              {groups.flatMap((g) =>
                (g.hosts ?? []).map((h) => (
                  <option key={`${g.id}-${h.id}`} value={String(h.id)}>
                    {h.hostname} ({g.name})
                  </option>
                )),
              )}
            </select>
          );
        }
        return null;
      })}
    </div>
  );
}
