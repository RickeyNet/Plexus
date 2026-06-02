import { useMemo, useState } from 'react';

import { useDeleteUpgradeCampaign, useUpgradeCampaigns } from '@/api/upgrades';
import { AlertDialog } from '@/components/AlertDialog';
import { ConfirmDialog } from '@/components/ConfirmDialog';

import { CampaignFormModal } from './CampaignFormModal';
import { CampaignViewerModal } from './CampaignViewerModal';
import {
  campaignStatusBadgeClass,
  campaignStatusLabel,
  formatBackupTimestamp,
  formatScheduledTime,
} from './helpers';

export function CampaignsTab() {
  const query = useUpgradeCampaigns();
  const remove = useDeleteUpgradeCampaign();
  const [search, setSearch] = useState('');
  const [createOpen, setCreateOpen] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [viewingId, setViewingId] = useState<number | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<{ id: number; name: string } | null>(
    null,
  );
  const [alert, setAlert] = useState<{ title: string; message: string } | null>(
    null,
  );

  const campaigns = useMemo(() => query.data || [], [query.data]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return campaigns;
    return campaigns.filter(
      (c) =>
        c.name?.toLowerCase().includes(q) ||
        c.description?.toLowerCase().includes(q) ||
        c.status?.toLowerCase().includes(q),
    );
  }, [campaigns, search]);

  const handleDeleteConfirm = () => {
    if (!deleteTarget) return;
    remove.mutate(deleteTarget.id, {
      onSuccess: () => setDeleteTarget(null),
      onError: (e) => {
        setDeleteTarget(null);
        setAlert({
          title: 'Delete failed',
          message: (e as Error).message,
        });
      },
    });
  };

  if (query.isPending) return <p className="text-muted">Loading…</p>;
  if (query.error) {
    return (
      <p style={{ color: 'var(--danger)' }}>
        Failed to load campaigns: {(query.error as Error).message}
      </p>
    );
  }

  return (
    <div>
      <div
        style={{
          display: 'flex',
          gap: '0.5rem',
          marginBottom: '0.75rem',
          alignItems: 'center',
        }}
      >
        <input
          type="search"
          className="form-input"
          placeholder="Search campaigns…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ flex: 1, maxWidth: 320 }}
        />
        <button
          type="button"
          className="btn btn-sm btn-primary"
          onClick={() => setCreateOpen(true)}
          style={{ marginLeft: 'auto' }}
        >
          New Campaign
        </button>
      </div>

      {filtered.length === 0 ? (
        <div className="empty-state" style={{ padding: '2rem' }}>
          {campaigns.length === 0
            ? 'No upgrade campaigns yet.'
            : 'No campaigns match the search.'}
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {filtered.map((c) => {
            const pct =
              c.device_count > 0
                ? Math.round((c.devices_completed / c.device_count) * 100)
                : 0;
            const sched = c.scheduled_at
              ? formatScheduledTime(c.scheduled_at)
              : null;
            return (
              <div
                key={c.id}
                className="card"
                style={{ padding: '0.75rem 1rem', cursor: 'pointer' }}
                onClick={() => setViewingId(c.id)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    setViewingId(c.id);
                  }
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    gap: '1rem',
                  }}
                >
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <h3 style={{ margin: '0 0 0.25rem' }}>{c.name}</h3>
                    {c.description && (
                      <p
                        style={{
                          margin: 0,
                          opacity: 0.7,
                          fontSize: '0.85em',
                        }}
                      >
                        {c.description}
                      </p>
                    )}
                  </div>
                  <div style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                    <span
                      className={`badge ${campaignStatusBadgeClass(
                        c.status,
                        c.is_actively_running,
                      )}`}
                    >
                      {campaignStatusLabel(c.status)}
                    </span>
                    <div
                      style={{
                        fontSize: '0.85em',
                        marginTop: '0.25rem',
                        opacity: 0.7,
                      }}
                    >
                      {c.devices_completed}/{c.device_count} devices · {pct}%
                    </div>
                  </div>
                </div>
                <div
                  style={{
                    marginTop: '0.5rem',
                    height: 6,
                    borderRadius: 3,
                    background: 'var(--glass-border)',
                    overflow: 'hidden',
                  }}
                >
                  <div
                    style={{
                      width: `${pct}%`,
                      height: '100%',
                      background: 'var(--success)',
                      transition: 'width 0.3s',
                    }}
                  />
                </div>
                {sched && (
                  <div
                    style={{
                      marginTop: '0.5rem',
                      padding: '0.4rem 0.6rem',
                      borderRadius: 6,
                      background: 'rgba(245, 158, 11, 0.12)',
                      color: 'var(--warning)',
                      fontSize: '0.85em',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.4rem',
                    }}
                  >
                    <span aria-hidden>⏰</span>
                    <span>
                      Reload scheduled for <strong>{sched.absolute}</strong>{' '}
                      <span style={{ opacity: 0.8 }}>({sched.relative})</span>
                    </span>
                  </div>
                )}
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    marginTop: '0.5rem',
                  }}
                  onClick={(e) => e.stopPropagation()}
                >
                  <span style={{ fontSize: '0.8em', opacity: 0.55 }}>
                    Created {formatBackupTimestamp(c.created_at).slice(0, 16)}
                    {c.created_by ? ` by ${c.created_by}` : ''}
                  </span>
                  <span style={{ display: 'flex', gap: '0.25rem' }}>
                    <button
                      type="button"
                      className="btn btn-sm btn-secondary"
                      onClick={(e) => {
                        e.stopPropagation();
                        setEditingId(c.id);
                      }}
                      disabled={c.is_actively_running}
                    >
                      Edit
                    </button>
                    <button
                      type="button"
                      className="btn btn-sm btn-danger"
                      onClick={(e) => {
                        e.stopPropagation();
                        setDeleteTarget({ id: c.id, name: c.name });
                      }}
                      disabled={c.is_actively_running || remove.isPending}
                    >
                      Delete
                    </button>
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {createOpen && (
        <CampaignFormModal
          mode="create"
          onClose={() => setCreateOpen(false)}
        />
      )}
      {editingId !== null && (
        <CampaignFormModal
          mode="edit"
          campaignId={editingId}
          onClose={() => setEditingId(null)}
        />
      )}
      {viewingId !== null && (
        <CampaignViewerModal
          campaignId={viewingId}
          onClose={() => setViewingId(null)}
        />
      )}
      <ConfirmDialog
        isOpen={deleteTarget !== null}
        title="Delete campaign?"
        message={
          <>
            Delete campaign <strong>{deleteTarget?.name}</strong>? This
            permanently removes it and its events.
          </>
        }
        confirmLabel="Delete"
        loading={remove.isPending}
        onCancel={() => {
          if (!remove.isPending) setDeleteTarget(null);
        }}
        onConfirm={handleDeleteConfirm}
      />
      <AlertDialog
        isOpen={alert !== null}
        title={alert?.title ?? ''}
        message={alert?.message ?? ''}
        variant="error"
        onClose={() => setAlert(null)}
      />
    </div>
  );
}
