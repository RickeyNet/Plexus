import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';

import { PageHelp } from '@/components/PageHelp';
import { useDialogs } from '@/components/DialogProvider-context';

import {
  type DhcpServer,
  type IpamSource,
  useDeleteDhcpServer,
  useDeleteIpamSource,
  useDhcpCorrelation,
  useDhcpExhaustion,
  useDhcpServers,
  useIpamOverview,
  useIpamSources,
  useIpamSubnetDetail,
  useIpamSyncConfig,
  useReconcileDiffs,
  useReconcileRuns,
  useResolveDiff,
  useRunReconcile,
  useSyncDhcpServer,
  useSyncIpamSource,
} from '@/api/ipam';
import { useInventoryGroups } from '@/api/compliance';

import { DefineSubnetModal } from './DefineSubnetModal';
import { DhcpServerModal } from './DhcpServerModal';
import { IpamSourceModal } from './IpamSourceModal';
import { SubnetDrilldown } from './SubnetDrilldown';
import { SyncScheduleModal } from './SyncScheduleModal';
import {
  driftBadgeClass,
  driftLabel,
  formatSubnetPreview,
  formatSyncTime,
  statusBadgeClass,
} from './helpers';

type ModalState =
  | { kind: 'none' }
  | { kind: 'define-subnet' }
  | { kind: 'source'; source: IpamSource | null }
  | { kind: 'dhcp'; server: DhcpServer | null }
  | { kind: 'schedule' };

export function Ipam() {
  const qc = useQueryClient();
  const [groupId, setGroupId] = useState<number | null>(null);
  const [includeCloud, setIncludeCloud] = useState(true);
  const [selectedSubnet, setSelectedSubnet] = useState<string>('');
  const [modal, setModal] = useState<ModalState>({ kind: 'none' });

  const groups = useInventoryGroups();
  const overview = useIpamOverview(groupId, includeCloud);
  const sources = useIpamSources();
  const syncConfig = useIpamSyncConfig();
  const reconcileRuns = useReconcileRuns();
  const reconcileDiffs = useReconcileDiffs();
  const dhcpServers = useDhcpServers();
  const dhcpExhaustion = useDhcpExhaustion();
  const dhcpCorrelation = useDhcpCorrelation();

  const subnetDetail = useIpamSubnetDetail(
    selectedSubnet || null,
    groupId,
    includeCloud,
  );

  const summary = overview.data?.summary ?? {};
  const subnets = overview.data?.subnets ?? [];
  const duplicates = overview.data?.duplicate_ips ?? [];
  const sourceList = sources.data?.sources ?? [];
  const config = syncConfig.data?.config ?? { enabled: true, interval_seconds: 1800 };
  const intervalMin = Math.round((config.interval_seconds ?? 1800) / 60);

  const handleRefresh = () => {
    // Query keys must match the hyphenated keys registered in api/ipam.ts
    // (KEYS). The previous camelCase strings never matched, so Refresh silently
    // no-op'd the reconcile and DHCP panels.
    qc.invalidateQueries({ queryKey: ['ipam-overview'] });
    qc.invalidateQueries({ queryKey: ['ipam-subnet-detail'] });
    qc.invalidateQueries({ queryKey: ['ipam-sources'] });
    qc.invalidateQueries({ queryKey: ['ipam-reconcile-runs'] });
    qc.invalidateQueries({ queryKey: ['ipam-reconcile-diffs'] });
    qc.invalidateQueries({ queryKey: ['dhcp-servers'] });
    qc.invalidateQueries({ queryKey: ['dhcp-exhaustion'] });
    qc.invalidateQueries({ queryKey: ['dhcp-correlation'] });
  };

  const summaryCards = [
    { label: 'Tracked Hosts', value: summary.inventory_host_count ?? 0 },
    { label: 'Total Subnets', value: summary.total_subnets ?? 0 },
    { label: 'Cloud CIDRs', value: summary.cloud_subnets ?? 0 },
    { label: 'External Subnets', value: summary.external_subnets ?? 0 },
    {
      label: 'Duplicate IPs',
      value: summary.duplicate_ip_count ?? 0,
      color: 'var(--danger-color)',
    },
    { label: 'Inventory Subnets', value: summary.inventory_subnets ?? 0 },
    { label: 'Local Subnets', value: summary.local_subnets ?? 0 },
    { label: 'External Allocations', value: summary.external_allocation_count ?? 0 },
    {
      label: 'Inventory / Cloud Overlaps',
      value: summary.exact_source_overlap_count ?? 0,
      color: 'var(--warning-color)',
    },
  ];

  return (
    <div>
      <div
        className="page-header"
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-end',
          gap: '1rem',
          flexWrap: 'wrap',
          marginBottom: '1rem',
        }}
      >
        <div>
          <h2 style={{ margin: 0 }}>IP Address Management</h2>
        </div>
        <div
          style={{
            display: 'flex',
            gap: '0.5rem',
            flexWrap: 'wrap',
            alignItems: 'end',
          }}
        >
          <label>
            Inventory Group{' '}
            <select
              className="form-select"
              value={groupId ?? ''}
              onChange={(e) =>
                setGroupId(e.target.value ? Number(e.target.value) : null)
              }
            >
              <option value="">All Groups</option>
              {(groups.data ?? []).map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name || `Group ${g.id}`}
                </option>
              ))}
            </select>
          </label>
          <label
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              margin: '0 0 0.2rem',
            }}
          >
            <input
              type="checkbox"
              checked={includeCloud}
              onChange={(e) => setIncludeCloud(e.target.checked)}
            />
            Include Cloud CIDRs
          </label>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={handleRefresh}
          >
            Refresh
          </button>
        </div>
      </div>

      <PageHelp
        pageKey="ipam"
        title="Address Space, Utilization & Conflicts"
        text="Review inferred on-prem subnets, discovered cloud CIDRs, and duplicate IP conflicts in one place so addressing issues are visible before they become outages."
      />

      <div style={{ marginBottom: '1rem' }}>
        <div
          className="stats-grid"
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
            gap: '1rem',
          }}
        >
          {summaryCards.map((card) => (
            <div key={card.label} className="stat-card">
              <div
                className="stat-value"
                style={card.color ? { color: card.color } : undefined}
              >
                {String(card.value)}
              </div>
              <div className="stat-label">{card.label}</div>
            </div>
          ))}
        </div>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'minmax(0, 2.1fr) minmax(320px, 1fr)',
          gap: '1rem',
          alignItems: 'start',
        }}
      >
        <div className="card" style={{ padding: '1rem', overflow: 'auto' }}>
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              gap: '1rem',
              marginBottom: '0.75rem',
              flexWrap: 'wrap',
            }}
          >
            <div>
              <h3 style={{ margin: 0 }}>Subnet Inventory</h3>
              <div
                className="text-muted"
                style={{ fontSize: '0.88em', marginTop: '0.2rem' }}
              >
                {subnets.length} visible subnet{subnets.length === 1 ? '' : 's'}
              </div>
            </div>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => setModal({ kind: 'define-subnet' })}
            >
              + Define Subnet
            </button>
          </div>
          {overview.isPending ? (
            <div className="text-muted">Loading subnet inventory...</div>
          ) : subnets.length === 0 ? (
            <div className="empty-state">
              <p>No IPAM data found for the current filter.</p>
            </div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Subnet</th>
                  <th>Capacity</th>
                  <th>Groups</th>
                  <th>Sources</th>
                  <th>Preview</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {subnets.map((item) => {
                  const groupNames = item.group_names ?? [];
                  const sourceTypes = item.source_types ?? [];
                  const externals = item.external_source_names_preview ?? [];
                  const vlans = item.vlan_ids ?? [];
                  const isSelected = selectedSubnet === item.subnet;
                  return (
                    <tr
                      key={item.subnet}
                      style={
                        isSelected
                          ? { background: 'rgba(255,255,255,0.04)' }
                          : undefined
                      }
                    >
                      <td>
                        <div style={{ fontWeight: 600 }}>{item.subnet}</div>
                        <div className="text-muted" style={{ fontSize: '0.85em' }}>
                          IPv{item.version ?? ''} /{item.prefix_length ?? ''} ·{' '}
                          {item.total_addresses ?? 0} addresses
                        </div>
                        {(item.vrf_name || vlans.length > 0) && (
                          <div style={{ marginTop: '0.25rem' }}>
                            {item.vrf_name && (
                              <span
                                className="badge"
                                style={{
                                  background: 'rgba(99,102,241,0.18)',
                                  color: '#a5b4fc',
                                  fontSize: '0.7em',
                                  marginRight: '0.3rem',
                                }}
                              >
                                VRF: {item.vrf_name}
                              </span>
                            )}
                            {vlans.map((v) => (
                              <span
                                key={String(v)}
                                className="badge"
                                style={{
                                  background: 'rgba(34,197,94,0.18)',
                                  color: '#86efac',
                                  fontSize: '0.7em',
                                  marginRight: '0.3rem',
                                }}
                              >
                                VLAN {v}
                              </span>
                            ))}
                          </div>
                        )}
                      </td>
                      <td>
                        <div>{item.available_address_count ?? 0} available</div>
                        <div className="text-muted" style={{ fontSize: '0.85em' }}>
                          {item.allocated_address_count ?? 0} allocated ·{' '}
                          {item.reserved_address_count ?? 0} reserved
                        </div>
                        <div className="text-muted" style={{ fontSize: '0.85em' }}>
                          {item.utilization_pct ?? 0}% utilized
                        </div>
                      </td>
                      <td>
                        {groupNames.length ? (
                          groupNames.join(', ')
                        ) : (
                          <span className="text-muted">No inventory groups</span>
                        )}
                      </td>
                      <td>
                        {sourceTypes.map((s) => (
                          <span
                            key={`st-${s}`}
                            className="badge badge-secondary"
                            style={{
                              marginRight: '0.35rem',
                              marginBottom: '0.35rem',
                            }}
                          >
                            {s}
                          </span>
                        ))}
                        {externals.map((s) => (
                          <span
                            key={`ext-${s}`}
                            className="badge badge-secondary"
                            style={{
                              marginRight: '0.35rem',
                              marginBottom: '0.35rem',
                            }}
                          >
                            {s}
                          </span>
                        ))}
                      </td>
                      <td className="text-muted" style={{ maxWidth: 420 }}>
                        {formatSubnetPreview(item)}
                      </td>
                      <td>
                        <button
                          type="button"
                          className="btn btn-secondary"
                          onClick={() => setSelectedSubnet(item.subnet)}
                        >
                          Drilldown
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        <div style={{ display: 'grid', gap: '1rem' }}>
          <div className="card" style={{ padding: '1rem' }}>
            <h3 style={{ margin: '0 0 0.75rem' }}>Subnet Drilldown</h3>
            {selectedSubnet ? (
              <SubnetDrilldown
                subnet={selectedSubnet}
                detail={subnetDetail.data}
                isLoading={subnetDetail.isPending}
                onRefresh={() =>
                  qc.invalidateQueries({ queryKey: ['ipam-subnet-detail'] })
                }
              />
            ) : (
              <p className="text-muted" style={{ margin: 0 }}>
                Select a subnet to inspect allocations, reserved ranges, and
                first-available capacity.
              </p>
            )}
          </div>

          <SourcesCard
            sources={sourceList}
            syncEnabled={config.enabled}
            intervalMin={intervalMin}
            onAddSource={() => setModal({ kind: 'source', source: null })}
            onEditSource={(s) => setModal({ kind: 'source', source: s })}
            onSchedule={() => setModal({ kind: 'schedule' })}
          />

          <ReconcileCard
            runs={reconcileRuns.data?.runs ?? []}
            diffs={reconcileDiffs.data?.diffs ?? []}
            sources={sourceList}
          />

          <DhcpCard
            servers={dhcpServers.data?.servers ?? []}
            exhaustion={
              dhcpExhaustion.data ?? {
                exhausted: [],
                near_exhaustion: [],
                threshold_pct: 90,
              }
            }
            correlation={
              dhcpCorrelation.data ?? {
                totals: { known: 0, unknown: 0 },
                known: [],
                unknown: [],
              }
            }
            onAdd={() => setModal({ kind: 'dhcp', server: null })}
            onEdit={(s) => setModal({ kind: 'dhcp', server: s })}
          />

          <div className="card" style={{ padding: '1rem' }}>
            <h3 style={{ margin: '0 0 0.75rem' }}>Duplicate IP Conflicts</h3>
            {duplicates.length === 0 ? (
              <p className="text-muted" style={{ margin: 0 }}>
                No duplicate inventory IPs detected for the current scope.
              </p>
            ) : (
              duplicates.map((item) => (
                <div
                  key={`${item.ip_address}-${item.vrf_name ?? ''}`}
                  style={{
                    padding: '0.8rem 0',
                    borderBottom: '1px solid rgba(255,255,255,0.08)',
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      gap: '0.75rem',
                      alignItems: 'flex-start',
                    }}
                  >
                    <div>
                      <div
                        style={{
                          fontWeight: 600,
                          color: 'var(--danger-color)',
                        }}
                      >
                        {item.ip_address || ''}
                        {item.vrf_name && (
                          <span
                            className="badge"
                            style={{
                              background: 'rgba(99,102,241,0.18)',
                              color: '#a5b4fc',
                              fontSize: '0.7em',
                              marginLeft: '0.4rem',
                            }}
                          >
                            VRF: {item.vrf_name}
                          </span>
                        )}
                      </div>
                      <div className="text-muted" style={{ fontSize: '0.9em' }}>
                        {item.host_count ?? 0} inventory entries
                        {item.vrf_name ? ' · same VRF' : ''}
                      </div>
                    </div>
                    <span className="badge badge-danger">Conflict</span>
                  </div>
                  <div
                    style={{
                      display: 'grid',
                      gap: '0.45rem',
                      marginTop: '0.65rem',
                    }}
                  >
                    {(item.hosts ?? []).map((host, i) => (
                      <div
                        key={i}
                        className="text-muted"
                        style={{ lineHeight: 1.45 }}
                      >
                        <strong style={{ color: 'var(--text-primary)' }}>
                          {host.hostname || 'Unknown host'}
                        </strong>
                        <span> in {host.group_name || 'Unknown group'}</span>
                        {host.status && <span> · {host.status}</span>}
                      </div>
                    ))}
                  </div>
                </div>
              ))
            )}
          </div>

          <div className="card" style={{ padding: '1rem' }}>
            <h3 style={{ margin: '0 0 0.75rem' }}>Scope Notes</h3>
            <div
              className="text-muted"
              style={{ display: 'grid', gap: '0.65rem', lineHeight: 1.55 }}
            >
              <div>
                Inventory subnets are inferred from host addresses. Plain IPv4
                addresses default to /24 and plain IPv6 addresses default to
                /64 when prefixes are not stored.
              </div>
              <div>
                Cloud CIDRs come from discovered cloud resources such as VPCs,
                VNets, and subnets.
              </div>
              <div>
                Available-address calculations subtract reserved ranges before
                utilization is computed, and the drilldown shows any
                allocations that collide with reserved space.
              </div>
              <div>
                Duplicate IP conflicts are detected across inventory groups so
                address reuse is visible even when each group stays internally
                unique.
              </div>
            </div>
          </div>
        </div>
      </div>

      {modal.kind === 'define-subnet' && (
        <DefineSubnetModal onClose={() => setModal({ kind: 'none' })} />
      )}
      {modal.kind === 'source' && (
        <IpamSourceModal
          source={modal.source}
          onClose={() => setModal({ kind: 'none' })}
        />
      )}
      {modal.kind === 'dhcp' && (
        <DhcpServerModal
          server={modal.server}
          onClose={() => setModal({ kind: 'none' })}
        />
      )}
      {modal.kind === 'schedule' && (
        <SyncScheduleModal
          config={config}
          onClose={() => setModal({ kind: 'none' })}
        />
      )}
    </div>
  );
}

interface SourcesCardProps {
  sources: IpamSource[];
  syncEnabled: boolean;
  intervalMin: number;
  onAddSource: () => void;
  onEditSource: (s: IpamSource) => void;
  onSchedule: () => void;
}

function SourcesCard({
  sources,
  syncEnabled,
  intervalMin,
  onAddSource,
  onEditSource,
  onSchedule,
}: SourcesCardProps) {
  const { confirm, alert } = useDialogs();
  const sync = useSyncIpamSource();
  const reconcile = useRunReconcile();
  const remove = useDeleteIpamSource();

  const handleSync = (id: number) => {
    sync.mutate(id, {
      onError: (e) => {
        void alert({ message: `Sync failed: ${(e as Error).message}`, variant: 'error' });
      },
    });
  };

  const handleReconcile = (id: number) => {
    reconcile.mutate(id, {
      onSuccess: (result) => {
        const count = Number(result?.summary?.diff_count ?? 0);
        void alert(
          count
            ? `Reconciliation complete - ${count} drift${count === 1 ? '' : 's'} detected.`
            : 'Reconciliation complete - no drift detected.',
        );
      },
      onError: (e) => {
        void alert({
          message: `Reconciliation failed: ${(e as Error).message}`,
          variant: 'error',
        });
      },
    });
  };

  const handleDelete = async (id: number, name: string) => {
    if (
      !(await confirm(
        `Delete IPAM source "${name}"? This also removes all synced prefixes and allocations.`,
      ))
    )
      return;
    remove.mutate(id, {
      onError: (e) => {
        void alert({ message: (e as Error).message, variant: 'error' });
      },
    });
  };

  return (
    <div className="card" style={{ padding: '1rem' }}>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '0.75rem',
          marginBottom: '0.75rem',
          flexWrap: 'wrap',
        }}
      >
        <h3 style={{ margin: 0 }}>External IPAM Sources</h3>
        <button type="button" className="btn btn-primary" onClick={onAddSource}>
          + Add Source
        </button>
      </div>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.75rem',
          flexWrap: 'wrap',
          padding: '0.6rem 0.75rem',
          background: 'rgba(255,255,255,0.03)',
          borderRadius: 8,
          marginBottom: '0.75rem',
        }}
      >
        <span
          className={`badge ${syncEnabled ? 'badge-success' : 'badge-secondary'}`}
        >
          {syncEnabled ? 'Auto-sync on' : 'Auto-sync off'}
        </span>
        <span className="text-muted" style={{ fontSize: '0.9em' }}>
          Every {intervalMin} min
        </span>
        <button
          type="button"
          className="btn btn-secondary"
          style={{
            padding: '0.2rem 0.55rem',
            fontSize: '0.82em',
            marginLeft: 'auto',
          }}
          onClick={onSchedule}
        >
          Schedule
        </button>
      </div>
      {sources.length === 0 ? (
        <p className="text-muted" style={{ margin: 0 }}>
          No external IPAM sources configured. Add one to start syncing
          subnets and allocations.
        </p>
      ) : (
        sources.map((src) => (
          <div
            key={src.id}
            style={{
              padding: '0.75rem 0',
              borderBottom: '1px solid rgba(255,255,255,0.08)',
            }}
          >
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                gap: '0.75rem',
                alignItems: 'flex-start',
                flexWrap: 'wrap',
              }}
            >
              <div>
                <div style={{ fontWeight: 600 }}>{src.name}</div>
                <div className="text-muted" style={{ fontSize: '0.85em' }}>
                  {src.provider} · {src.base_url}
                </div>
              </div>
              <div
                style={{
                  display: 'flex',
                  gap: '0.4rem',
                  flexWrap: 'wrap',
                  alignItems: 'center',
                }}
              >
                <span className={`badge ${statusBadgeClass(src.last_sync_status)}`}>
                  {src.last_sync_status || 'never'}
                </span>
                {!src.enabled && (
                  <span className="badge badge-secondary">Disabled</span>
                )}
                {src.push_enabled && (
                  <span className="badge badge-success">Push on</span>
                )}
              </div>
            </div>
            <div
              className="text-muted"
              style={{ fontSize: '0.82em', margin: '0.3rem 0' }}
            >
              {formatSyncTime(src.last_sync_at)}
              {src.last_sync_message ? ` · ${src.last_sync_message}` : ''}
            </div>
            <div
              style={{ fontSize: '0.82em', color: 'var(--text-muted)' }}
            >
              {src.prefix_count ?? 0} subnets · {src.allocation_count ?? 0}{' '}
              allocations
            </div>
            <div
              style={{
                display: 'flex',
                gap: '0.5rem',
                marginTop: '0.5rem',
                flexWrap: 'wrap',
              }}
            >
              <button
                type="button"
                className="btn btn-primary"
                style={{ fontSize: '0.82em', padding: '0.25rem 0.6rem' }}
                onClick={() => handleSync(src.id)}
                disabled={sync.isPending}
              >
                Sync Now
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                style={{ fontSize: '0.82em', padding: '0.25rem 0.6rem' }}
                onClick={() => handleReconcile(src.id)}
                disabled={reconcile.isPending}
              >
                Reconcile
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                style={{ fontSize: '0.82em', padding: '0.25rem 0.6rem' }}
                onClick={() => onEditSource(src)}
              >
                Edit
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                style={{
                  fontSize: '0.82em',
                  padding: '0.25rem 0.6rem',
                  color: 'var(--danger-color)',
                }}
                onClick={() => handleDelete(src.id, src.name)}
              >
                Delete
              </button>
            </div>
          </div>
        ))
      )}
    </div>
  );
}

interface ReconcileCardProps {
  runs: ReturnType<typeof useReconcileRuns>['data'] extends infer T
    ? T extends { runs: infer R }
      ? R
      : never
    : never;
  diffs: ReturnType<typeof useReconcileDiffs>['data'] extends infer T
    ? T extends { diffs: infer R }
      ? R
      : never
    : never;
  sources: IpamSource[];
}

function ReconcileCard({ runs, diffs, sources }: ReconcileCardProps) {
  const { alert } = useDialogs();
  const resolve = useResolveDiff();
  const sourceById = new Map(sources.map((s) => [s.id, s]));
  const recentRuns = runs.slice(0, 5);

  const handleResolve = (
    diffId: number,
    resolution: 'accept_plexus' | 'accept_ipam' | 'ignored',
  ) => {
    resolve.mutate(
      { diffId, resolution },
      {
        onError: (e) => {
          void alert({
            message: `Failed to resolve drift: ${(e as Error).message}`,
            variant: 'error',
          });
        },
      },
    );
  };

  return (
    <div className="card" style={{ padding: '1rem' }}>
      <div style={{ marginBottom: '0.75rem' }}>
        <h3 style={{ margin: 0 }}>Reconciliation</h3>
        <div
          className="text-muted"
          style={{ fontSize: '0.85em', marginTop: '0.2rem' }}
        >
          Detects drift between Plexus inventory and external IPAM allocations.
        </div>
      </div>

      <div style={{ marginBottom: '0.75rem' }}>
        {recentRuns.length === 0 ? (
          <div className="text-muted" style={{ fontSize: '0.85em' }}>
            No reconciliation runs yet. Click "Reconcile" on a source to start.
          </div>
        ) : (
          <>
            <div
              style={{
                fontWeight: 600,
                marginBottom: '0.4rem',
                fontSize: '0.9em',
              }}
            >
              Recent Runs
            </div>
            <table className="data-table" style={{ fontSize: '0.85em' }}>
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Started</th>
                  <th>Status</th>
                  <th>Drifts</th>
                  <th>Resolved</th>
                </tr>
              </thead>
              <tbody>
                {recentRuns.map((run) => {
                  const src = sourceById.get(run.source_id);
                  return (
                    <tr key={run.id}>
                      <td>{src ? src.name : `Source #${run.source_id}`}</td>
                      <td>{formatSyncTime(run.started_at)}</td>
                      <td>
                        <span className={`badge ${statusBadgeClass(run.status)}`}>
                          {run.status}
                        </span>
                      </td>
                      <td>{run.diff_count ?? 0}</td>
                      <td>{run.resolved_count ?? 0}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </>
        )}
      </div>

      {diffs.length === 0 ? (
        <div className="text-muted" style={{ fontSize: '0.85em' }}>
          No open drifts.
        </div>
      ) : (
        <>
          <div
            style={{
              fontWeight: 600,
              marginBottom: '0.4rem',
              fontSize: '0.9em',
            }}
          >
            Open Drifts ({diffs.length})
          </div>
          <table className="data-table" style={{ fontSize: '0.85em' }}>
            <thead>
              <tr>
                <th>Address</th>
                <th>Drift</th>
                <th>Source</th>
                <th>Plexus</th>
                <th>IPAM</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {diffs.map((diff) => {
                const src = sourceById.get(diff.source_id);
                const plexusHost = diff.plexus_state?.hostname || '';
                const ipamHost = diff.ipam_state?.dns_name || '';
                const ipamStatus = diff.ipam_state?.status || '';
                const pushAvailable =
                  src?.push_enabled && diff.drift_type !== 'missing_in_plexus';
                return (
                  <tr key={diff.id}>
                    <td>
                      <code>{diff.address}</code>
                    </td>
                    <td>
                      <span
                        className={`badge ${driftBadgeClass(diff.drift_type)}`}
                      >
                        {driftLabel(diff.drift_type)}
                      </span>
                    </td>
                    <td>{src ? src.name : `Source #${diff.source_id}`}</td>
                    <td>{plexusHost || '-'}</td>
                    <td>
                      {ipamHost || '-'}
                      {ipamStatus && (
                        <span className="text-muted"> ({ipamStatus})</span>
                      )}
                    </td>
                    <td style={{ whiteSpace: 'nowrap' }}>
                      {pushAvailable && (
                        <button
                          type="button"
                          className="btn btn-primary"
                          style={{
                            fontSize: '0.78em',
                            padding: '0.18rem 0.45rem',
                          }}
                          onClick={() =>
                            handleResolve(diff.id, 'accept_plexus')
                          }
                        >
                          Push to IPAM
                        </button>
                      )}
                      <button
                        type="button"
                        className="btn btn-secondary"
                        style={{
                          fontSize: '0.78em',
                          padding: '0.18rem 0.45rem',
                          marginLeft: pushAvailable ? '0.3rem' : 0,
                        }}
                        onClick={() => handleResolve(diff.id, 'accept_ipam')}
                      >
                        Accept IPAM
                      </button>
                      <button
                        type="button"
                        className="btn btn-secondary"
                        style={{
                          fontSize: '0.78em',
                          padding: '0.18rem 0.45rem',
                          marginLeft: '0.3rem',
                        }}
                        onClick={() => handleResolve(diff.id, 'ignored')}
                      >
                        Ignore
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}

interface DhcpCardProps {
  servers: DhcpServer[];
  exhaustion: NonNullable<ReturnType<typeof useDhcpExhaustion>['data']>;
  correlation: NonNullable<ReturnType<typeof useDhcpCorrelation>['data']>;
  onAdd: () => void;
  onEdit: (s: DhcpServer) => void;
}

function DhcpCard({
  servers,
  exhaustion,
  correlation,
  onAdd,
  onEdit,
}: DhcpCardProps) {
  const { confirm, alert } = useDialogs();
  const sync = useSyncDhcpServer();
  const remove = useDeleteDhcpServer();

  const handleSync = (id: number) => {
    sync.mutate(id, {
      onError: (e) => {
        void alert({
          message: `DHCP sync failed: ${(e as Error).message}`,
          variant: 'error',
        });
      },
    });
  };

  const handleDelete = async (id: number) => {
    if (!(await confirm('Delete this DHCP server and all cached scope/lease data?')))
      return;
    remove.mutate(id, {
      onError: (e) => {
        void alert({ message: (e as Error).message, variant: 'error' });
      },
    });
  };

  const exhaustedRows = [...exhaustion.exhausted, ...exhaustion.near_exhaustion];
  const unknown = correlation.unknown ?? [];

  return (
    <div className="card" style={{ padding: '1rem' }}>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '0.75rem',
          marginBottom: '0.75rem',
          flexWrap: 'wrap',
        }}
      >
        <div>
          <h3 style={{ margin: 0 }}>DHCP Servers</h3>
          <div
            className="text-muted"
            style={{ fontSize: '0.85em', marginTop: '0.2rem' }}
          >
            Pull scope utilization and active leases from Kea, Windows DHCP, or
            Infoblox.
          </div>
        </div>
        <button type="button" className="btn btn-primary" onClick={onAdd}>
          + Add DHCP Server
        </button>
      </div>

      <div style={{ marginBottom: '0.75rem' }}>
        {servers.length === 0 ? (
          <div className="text-muted" style={{ fontSize: '0.9em' }}>
            No DHCP servers configured. Add one to begin pulling scope
            utilization and lease data.
          </div>
        ) : (
          <table className="data-table" style={{ margin: 0 }}>
            <thead>
              <tr>
                <th>Provider</th>
                <th>Name</th>
                <th>Status</th>
                <th>Scopes</th>
                <th>Leases</th>
                <th>Last Sync</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {servers.map((s) => (
                <tr key={s.id}>
                  <td>{s.provider}</td>
                  <td>
                    {s.name}
                    {!s.enabled && (
                      <span
                        className="badge badge-warning"
                        style={{ marginLeft: '0.4rem' }}
                      >
                        disabled
                      </span>
                    )}
                  </td>
                  <td>
                    <span className={`badge ${statusBadgeClass(s.last_sync_status)}`}>
                      {s.last_sync_status || 'never'}
                    </span>
                    {s.last_sync_message && (
                      <div className="text-muted" style={{ fontSize: '0.8em' }}>
                        {s.last_sync_message}
                      </div>
                    )}
                  </td>
                  <td>{s.scope_count ?? 0}</td>
                  <td>{s.lease_count ?? 0}</td>
                  <td>{formatSyncTime(s.last_sync_at)}</td>
                  <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={() => handleSync(s.id)}
                      disabled={sync.isPending}
                    >
                      Sync
                    </button>
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      style={{ marginLeft: '0.3rem' }}
                      onClick={() => onEdit(s)}
                    >
                      Edit
                    </button>
                    <button
                      type="button"
                      className="btn btn-danger btn-sm"
                      style={{ marginLeft: '0.3rem' }}
                      onClick={() => handleDelete(s.id)}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {exhaustedRows.length > 0 && (
        <div style={{ marginBottom: '0.75rem' }}>
          <div style={{ fontWeight: 600, marginBottom: '0.4rem' }}>
            Scope Utilization Alerts
          </div>
          <table className="data-table" style={{ margin: 0 }}>
            <thead>
              <tr>
                <th>Subnet</th>
                <th>Name</th>
                <th>Used</th>
                <th>Utilization</th>
              </tr>
            </thead>
            <tbody>
              {exhaustedRows.map((s) => (
                <tr key={`${s.subnet}-${s.name ?? ''}`}>
                  <td>{s.subnet}</td>
                  <td>{s.name || ''}</td>
                  <td>
                    {s.used_addresses}/{s.total_addresses}
                  </td>
                  <td>
                    <span
                      style={{
                        color: s.exhausted
                          ? 'var(--danger-color)'
                          : 'var(--warning-color)',
                        fontWeight: 600,
                      }}
                    >
                      {s.utilization_pct}%
                    </span>{' '}
                    {s.exhausted ? (
                      <span
                        className="badge badge-danger"
                        style={{ marginLeft: '0.4rem' }}
                      >
                        EXHAUSTED
                      </span>
                    ) : (
                      <span
                        className="badge badge-warning"
                        style={{ marginLeft: '0.4rem' }}
                      >
                        near
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div>
        <div style={{ fontWeight: 600, marginBottom: '0.4rem' }}>
          Lease Correlation
        </div>
        <div
          className="text-muted"
          style={{ fontSize: '0.88em', marginBottom: '0.5rem' }}
        >
          {correlation.totals.known} known / {correlation.totals.unknown}{' '}
          unknown leases against discovered inventory.
        </div>
        {unknown.length === 0 ? (
          <div className="text-muted" style={{ fontSize: '0.85em' }}>
            All leases match a discovered inventory host.
          </div>
        ) : (
          <>
            <table className="data-table" style={{ margin: 0 }}>
              <thead>
                <tr>
                  <th>Address</th>
                  <th>MAC</th>
                  <th>Hostname</th>
                  <th>Scope</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {unknown.slice(0, 25).map((lease, i) => (
                  <tr key={`${lease.address}-${i}`}>
                    <td>{lease.address}</td>
                    <td>{lease.mac_address || ''}</td>
                    <td>{lease.hostname || ''}</td>
                    <td>{lease.scope_subnet || ''}</td>
                    <td>
                      <span className="badge badge-warning">unknown</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {unknown.length > 25 && (
              <div
                className="text-muted"
                style={{ fontSize: '0.8em', marginTop: '0.4rem' }}
              >
                …and {unknown.length - 25} more.
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
