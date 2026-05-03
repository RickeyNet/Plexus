import { useState } from 'react';

import {
  FederationOverview,
  FederationOverviewTotals,
  FederationPeer,
  FederationPeerDetail,
  useDeleteFederationPeer,
  useFederationOverview,
  useFederationPeers,
  useSyncFederationPeer,
  useTestFederationPeer,
} from '@/api/federation';

import { PeerFormModal } from './PeerFormModal';

export function Federation() {
  const peers = useFederationPeers();
  const overview = useFederationOverview();
  const [editing, setEditing] = useState<FederationPeer | null>(null);
  const [adding, setAdding] = useState(false);

  return (
    <>
      <div className="page-header">
        <h2>Federation Overview</h2>
        <button
          type="button"
          className="btn btn-primary"
          onClick={() => setAdding(true)}
        >
          Add Peer
        </button>
      </div>

      <details
        style={{
          border: '1px solid var(--border)',
          background: 'var(--bg-secondary)',
          borderRadius: '0.5rem',
          padding: '0.5rem 1rem',
          marginBottom: '1rem',
        }}
      >
        <summary
          style={{
            display: 'flex',
            gap: '0.6rem',
            alignItems: 'center',
            cursor: 'pointer',
            fontSize: '0.9rem',
            color: 'var(--text)',
            listStyle: 'none',
          }}
        >
          <InfoIcon />
          <strong>What is Federation?</strong>
        </summary>
        <div
          style={{
            fontSize: '0.85rem',
            lineHeight: 1.45,
            color: 'var(--text-muted)',
            padding: '0.5rem 0 0.25rem 2.4rem',
          }}
        >
          <p style={{ margin: '0 0 0.4rem 0' }}>
            Federation lets you connect multiple Plexus instances together so
            this UI can show aggregated device counts, alerts, and health
            across all of them — useful for MSPs managing multiple customer
            networks or organizations with regional deployments (e.g. NA, EU,
            APAC). Each peer remains independent and authoritative for its
            own data; this view is read-only aggregation over HTTPS using the
            remote's API token.
          </p>
          <p style={{ margin: 0 }}>
            <strong style={{ color: 'var(--text)' }}>You don't need this if:</strong>{' '}
            you only run a single Plexus instance. In that case, you can hide
            it from the sidebar via Settings → Feature Visibility.
          </p>
        </div>
      </details>

      <OverviewCards data={overview.data} loading={overview.isPending} />

      <h3 style={{ marginTop: '1.5rem' }}>Registered Peers</h3>

      {peers.isPending && <div className="loading">Loading peers…</div>}
      {peers.error && (
        <div className="error">
          <strong>Failed to load peers:</strong> {peers.error.message}
        </div>
      )}
      {peers.data && (
        <PeerTable
          peers={peers.data}
          onEdit={(p) => setEditing(p)}
          onAddPeer={() => setAdding(true)}
        />
      )}

      <PeerDetailCards peers={overview.data?.peers ?? []} />

      {(adding || editing) && (
        <PeerFormModal
          existing={editing}
          onClose={() => {
            setAdding(false);
            setEditing(null);
          }}
        />
      )}
    </>
  );
}

// ── Overview cards ─────────────────────────────────────────────────────────

const STAT_COLORS: Record<keyof FederationOverviewTotals, string | undefined> = {
  total_peers: undefined,
  healthy_peers: undefined,
  total_devices: undefined,
  devices_up: 'var(--success)',
  devices_down: 'var(--danger)',
  total_alerts: 'var(--warning)',
  critical_alerts: 'var(--danger)',
};

const STAT_LABELS: Record<keyof FederationOverviewTotals, string> = {
  total_peers: 'Total Peers',
  healthy_peers: 'Healthy Peers',
  total_devices: 'Total Devices',
  devices_up: 'Devices Up',
  devices_down: 'Devices Down',
  total_alerts: 'Active Alerts',
  critical_alerts: 'Critical Alerts',
};

const STAT_ORDER: (keyof FederationOverviewTotals)[] = [
  'total_peers',
  'healthy_peers',
  'total_devices',
  'devices_up',
  'devices_down',
  'total_alerts',
  'critical_alerts',
];

function OverviewCards({
  data,
  loading,
}: {
  data: FederationOverview | undefined;
  loading: boolean;
}) {
  if (loading) return <div className="skeleton-loader" style={{ height: 100 }} />;
  if (!data || !data.totals) {
    return (
      <p style={{ color: 'var(--text-muted)' }}>
        No overview data yet. Sync peers to see aggregated metrics.
      </p>
    );
  }
  const t = data.totals;
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
        gap: '1rem',
        marginBottom: '1.5rem',
      }}
    >
      {STAT_ORDER.map((key) => (
        <div className="stat-card" key={key}>
          <div className="stat-value" style={{ color: STAT_COLORS[key] }}>
            {t[key] ?? 0}
          </div>
          <div className="stat-label">{STAT_LABELS[key]}</div>
        </div>
      ))}
    </div>
  );
}

// ── Peer table ─────────────────────────────────────────────────────────────

function PeerTable({
  peers,
  onEdit,
  onAddPeer,
}: {
  peers: FederationPeer[];
  onEdit: (p: FederationPeer) => void;
  onAddPeer: () => void;
}) {
  if (peers.length === 0) {
    return (
      <div className="empty-state">
        <p>No federation peers configured.</p>
        <button type="button" className="btn btn-primary" onClick={onAddPeer}>
          Add Peer
        </button>
      </div>
    );
  }
  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>Name</th>
          <th>URL</th>
          <th>Status</th>
          <th>Sync</th>
          <th>Last Synced</th>
          <th>Token</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {peers.map((p) => (
          <PeerRow key={p.id} peer={p} onEdit={() => onEdit(p)} />
        ))}
      </tbody>
    </table>
  );
}

function PeerRow({ peer, onEdit }: { peer: FederationPeer; onEdit: () => void }) {
  const test = useTestFederationPeer();
  const sync = useSyncFederationPeer();
  const remove = useDeleteFederationPeer();

  return (
    <tr>
      <td>{peer.name}</td>
      <td>
        <code>{peer.url}</code>
      </td>
      <td><EnabledBadge enabled={peer.enabled} /></td>
      <td><SyncStatusBadge status={peer.last_sync_status} /></td>
      <td>
        {peer.last_sync_at ? (
          formatDate(peer.last_sync_at)
        ) : (
          <span style={{ color: 'var(--text-muted)' }}>—</span>
        )}
      </td>
      <td>
        {peer.has_token ? (
          <span className="badge badge-info">Yes</span>
        ) : (
          <span style={{ color: 'var(--text-muted)' }}>No</span>
        )}
      </td>
      <td>
        <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap' }}>
          <button
            type="button"
            className="btn btn-sm btn-secondary"
            disabled={test.isPending}
            title="Test Connection"
            onClick={async () => {
              try {
                const result = await test.mutateAsync(peer.id);
                if (result.status === 'ok') {
                  alert(
                    `Connection OK — remote version: ${result.remote_version || 'unknown'}`,
                  );
                } else {
                  alert(`Connection failed: ${result.message || 'Unknown error'}`);
                }
              } catch (err) {
                alert(`Test failed: ${err instanceof Error ? err.message : String(err)}`);
              }
            }}
          >
            {test.isPending ? '…' : 'Test'}
          </button>
          <button
            type="button"
            className="btn btn-sm btn-primary"
            disabled={sync.isPending}
            title="Sync Now"
            onClick={async () => {
              try {
                await sync.mutateAsync(peer.id);
              } catch (err) {
                alert(`Sync failed: ${err instanceof Error ? err.message : String(err)}`);
              }
            }}
          >
            {sync.isPending ? '…' : 'Sync'}
          </button>
          <button
            type="button"
            className="btn btn-sm btn-secondary"
            title="Edit"
            onClick={onEdit}
          >
            Edit
          </button>
          <button
            type="button"
            className="btn btn-sm btn-danger"
            disabled={remove.isPending}
            title="Delete"
            onClick={async () => {
              if (
                !confirm(
                  `Delete peer "${peer.name}"?\n\nThis will remove the peer and all cached sync data.`,
                )
              )
                return;
              try {
                await remove.mutateAsync(peer.id);
              } catch (err) {
                alert(`Delete failed: ${err instanceof Error ? err.message : String(err)}`);
              }
            }}
          >
            Del
          </button>
        </div>
      </td>
    </tr>
  );
}

function EnabledBadge({ enabled }: { enabled: boolean }) {
  return enabled ? (
    <span className="badge badge-success">Enabled</span>
  ) : (
    <span className="badge badge-secondary">Disabled</span>
  );
}

function SyncStatusBadge({ status }: { status?: string | null }) {
  const s = String(status || 'never').toLowerCase();
  if (s === 'ok') return <span className="badge badge-success">Synced</span>;
  if (s === 'error') return <span className="badge badge-danger">Error</span>;
  return <span className="badge badge-secondary">Never</span>;
}

// ── Per-peer detail cards ──────────────────────────────────────────────────

function PeerDetailCards({ peers }: { peers: FederationPeerDetail[] }) {
  if (peers.length === 0) return null;
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
        gap: '1rem',
        marginTop: '1rem',
      }}
    >
      {peers.map((p) => {
        const dev = p.devices ?? {};
        const alerts = p.alerts ?? {};
        const comp = p.compliance ?? {};
        return (
          <div className="card" key={p.id}>
            <h4 style={{ margin: '0 0 0.5rem 0' }}>{p.name}</h4>
            <div style={{ color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
              {p.url}
              {p.version ? ` — v${p.version}` : ''}
            </div>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))',
                gap: '0.5rem',
              }}
            >
              <div>
                <strong>{dev.total ?? 0}</strong> devices
              </div>
              <div style={{ color: 'var(--success)' }}>
                <strong>{dev.up ?? 0}</strong> up
              </div>
              <div style={{ color: 'var(--danger)' }}>
                <strong>{dev.down ?? 0}</strong> down
              </div>
              <div style={{ color: 'var(--warning)' }}>
                <strong>{alerts.active ?? 0}</strong> alerts
              </div>
              <div>
                <strong>{comp.total_profiles ?? 0}</strong> profiles
              </div>
            </div>
            <div style={{ color: 'var(--text-muted)', marginTop: '0.5rem', fontSize: '0.85em' }}>
              <SyncStatusBadge status={p.last_sync_status} />
              {p.last_sync_at ? ` — ${formatDate(p.last_sync_at)}` : ''}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Helpers ────────────────────────────────────────────────────────────────

function formatDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

function InfoIcon() {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      style={{ flexShrink: 0, color: 'var(--primary)' }}
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="10" />
      <line x1="12" y1="16" x2="12" y2="12" />
      <line x1="12" y1="8" x2="12.01" y2="8" />
    </svg>
  );
}
