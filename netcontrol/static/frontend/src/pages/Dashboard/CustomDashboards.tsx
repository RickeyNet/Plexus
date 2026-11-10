import { useState } from 'react';
import { Link } from 'react-router';

import { useCustomDashboards, useDeleteCustomDashboard } from '@/api/dashboard';
import { DeleteButton } from '@/components/DeleteButton';
import { useDialogs } from '@/components/DialogProvider-context';
import { PageHeader } from '@/components/PageHeader';
import { formatBackendDate } from '@/lib/datetime';

import { CreateDashboardModal } from './CreateDashboardModal';
import { DashboardSwitcher } from './DashboardSwitcher';

export function CustomDashboards() {
  const { confirm, alert } = useDialogs();
  const { data: dashboards = [], isPending, error } = useCustomDashboards();
  const deleteMutation = useDeleteCustomDashboard();
  const [showCreate, setShowCreate] = useState(false);

  return (
    <>
      <PageHeader title="Dashboards">
        <DashboardSwitcher current={null} />
        <button className="btn btn-primary" onClick={() => setShowCreate(true)}>
          + New Dashboard
        </button>
      </PageHeader>

      {isPending && (
        <div className="dashboards-card-grid">
          <div className="skeleton skeleton-card" />
          <div className="skeleton skeleton-card" />
          <div className="skeleton skeleton-card" />
        </div>
      )}

      {error && (
        <div className="glass-card card" style={{ borderColor: 'var(--danger)' }}>
          <strong>Failed to load dashboards:</strong> {(error as Error).message}
        </div>
      )}

      {!isPending && !error && dashboards.length === 0 && (
        <div className="empty-state">
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
          <p>No dashboards yet</p>
          <button className="btn btn-primary" onClick={() => setShowCreate(true)}>
            Create Your First Dashboard
          </button>
        </div>
      )}

      {dashboards.length > 0 && (
        <div className="dashboards-card-grid">
          {dashboards.map((d) => (
            <div key={d.id} className="card card-clickable dashboard-card">
              <div className="card-title">
                <Link to={`/dashboards/${d.id}`} className="dashboard-card-link">
                  {d.name}
                </Link>
              </div>
              <p className="text-muted" style={{ fontSize: '0.85rem', margin: '0.25rem 0' }}>
                {d.description || 'No description'}
              </p>
              <div className="dashboard-card-footer">
                <span className="text-muted" style={{ fontSize: '0.75rem' }}>
                  {d.updated_at ? formatBackendDate(d.updated_at) : ''}
                </span>
                <DeleteButton
                  aria-label={`Delete dashboard ${d.name}`}
                  busy={deleteMutation.isPending && deleteMutation.variables === d.id}
                  onClick={async () => {
                    if (
                      !(await confirm({
                        title: 'Delete dashboard',
                        message: `Delete dashboard "${d.name}"? All panels will be removed.`,
                        confirmLabel: 'Delete',
                      }))
                    )
                      return;
                    deleteMutation.mutate(d.id, {
                      onError: (e) => {
                        void alert({ message: (e as Error).message, variant: 'error' });
                      },
                    });
                  }}
                />
              </div>
            </div>
          ))}
        </div>
      )}

      <CreateDashboardModal isOpen={showCreate} onClose={() => setShowCreate(false)} />
    </>
  );
}
