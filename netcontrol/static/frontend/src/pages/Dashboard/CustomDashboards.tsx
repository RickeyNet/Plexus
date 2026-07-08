import { useState } from 'react';
import { Link } from 'react-router-dom';

import { useCustomDashboards, useDeleteCustomDashboard } from '@/api/dashboard';
import { useDialogs } from '@/components/DialogProvider-context';
import { formatBackendDate } from '@/lib/datetime';

import { CreateDashboardModal } from './CreateDashboardModal';

export function CustomDashboards() {
  const { confirm } = useDialogs();
  const { data: dashboards = [], isPending, error } = useCustomDashboards();
  const deleteMutation = useDeleteCustomDashboard();
  const [showCreate, setShowCreate] = useState(false);

  return (
    <>
      <div
        className="page-header"
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '0.75rem',
        }}
      >
        <h2 style={{ margin: 0 }}>Dashboards</h2>
        <button className="btn btn-primary" onClick={() => setShowCreate(true)}>
          + New Dashboard
        </button>
      </div>

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
            <Link
              key={d.id}
              to={`/dashboards/${d.id}`}
              className="card dashboard-card"
              style={{ textDecoration: 'none', color: 'inherit', display: 'block' }}
            >
              <div className="card-title">{d.name}</div>
              <p className="text-muted" style={{ fontSize: '0.85rem', margin: '0.25rem 0' }}>
                {d.description || 'No description'}
              </p>
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginTop: '0.5rem',
                }}
              >
                <span className="text-muted" style={{ fontSize: '0.75rem' }}>
                  {d.updated_at ? formatBackendDate(d.updated_at) : ''}
                </span>
                <button
                  className="btn btn-sm btn-danger"
                  title="Delete"
                  onClick={async (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    if (!(await confirm(`Delete "${d.name}"? All panels will be removed.`))) return;
                    deleteMutation.mutate(d.id);
                  }}
                >
                  ×
                </button>
              </div>
            </Link>
          ))}
        </div>
      )}

      <CreateDashboardModal isOpen={showCreate} onClose={() => setShowCreate(false)} />
    </>
  );
}
