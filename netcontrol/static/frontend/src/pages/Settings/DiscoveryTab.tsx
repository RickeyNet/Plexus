import { useEffect, useState } from 'react';

import {
  StpDiscoveryConfig,
  TopologyDiscoveryConfig,
  useDeleteStpRootPolicy,
  useInventoryGroupsList,
  useRunStpDiscovery,
  useRunTopologyDiscovery,
  useStpDiscoveryConfig,
  useStpRootPolicies,
  useTopologyDiscoveryConfig,
  useUpdateStpDiscoveryConfig,
  useUpdateTopologyDiscoveryConfig,
  useUpsertStpRootPolicy,
} from '@/api/settings';

function StatusLine({
  status,
}: {
  status: { kind: 'success' | 'error'; message: string } | null;
}) {
  if (!status) return null;
  return (
    <div
      className={status.kind === 'error' ? 'error' : ''}
      style={{
        marginTop: '0.5rem',
        color: status.kind === 'error' ? undefined : 'var(--success)',
      }}
    >
      {status.message}
    </div>
  );
}

function TopologyDiscoverySection() {
  const query = useTopologyDiscoveryConfig();
  const update = useUpdateTopologyDiscoveryConfig();
  const runNow = useRunTopologyDiscovery();
  const [draft, setDraft] = useState<TopologyDiscoveryConfig | null>(null);
  const [status, setStatus] = useState<{ kind: 'success' | 'error'; message: string } | null>(null);

  useEffect(() => {
    if (query.data) setDraft(query.data);
  }, [query.data]);

  if (query.isLoading || !draft) return <p className="text-muted">Loading…</p>;
  if (query.isError)
    return (
      <div className="error">
        Failed to load topology discovery: {(query.error as Error).message}
      </div>
    );

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        setStatus(null);
        update.mutate(draft, {
          onSuccess: () =>
            setStatus({
              kind: 'success',
              message: 'Topology discovery schedule saved',
            }),
          onError: (err) =>
            setStatus({
              kind: 'error',
              message: `Failed to save: ${(err as Error).message}`,
            }),
        });
      }}
    >
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem' }}>
        <label
          className="form-group"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.4rem',
          }}
        >
          <input
            type="checkbox"
            checked={draft.enabled}
            onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })}
          />
          <span>Enable scheduled topology discovery</span>
        </label>
        <div className="form-group" style={{ flex: '0 1 200px' }}>
          <label className="form-label">Interval (seconds)</label>
          <input
            type="number"
            min={60}
            className="form-input"
            value={draft.interval_seconds}
            onChange={(e) =>
              setDraft({ ...draft, interval_seconds: Number(e.target.value) })
            }
          />
        </div>
      </div>
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <button
          type="submit"
          className="btn btn-primary"
          disabled={update.isPending}
        >
          {update.isPending ? 'Saving…' : 'Save Schedule'}
        </button>
        <button
          type="button"
          className="btn btn-secondary"
          disabled={runNow.isPending}
          onClick={() => {
            setStatus(null);
            runNow.mutate(undefined, {
              onSuccess: (resp) => {
                const r = resp.result || {};
                const kind = (r.errors ?? 0) > 0 ? 'error' : 'success';
                setStatus({
                  kind,
                  message: `Topology discovery complete: ${r.groups_scanned ?? 0} groups, ${r.links_discovered ?? 0} links, ${r.errors ?? 0} errors`,
                });
              },
              onError: (err) =>
                setStatus({
                  kind: 'error',
                  message: `Topology discovery failed: ${(err as Error).message}`,
                }),
            });
          }}
        >
          {runNow.isPending ? 'Running…' : 'Run Now'}
        </button>
      </div>
      <StatusLine status={status} />
    </form>
  );
}

function StpDiscoverySection() {
  const query = useStpDiscoveryConfig();
  const update = useUpdateStpDiscoveryConfig();
  const runNow = useRunStpDiscovery();
  const [draft, setDraft] = useState<StpDiscoveryConfig | null>(null);
  const [status, setStatus] = useState<{ kind: 'success' | 'error'; message: string } | null>(null);

  useEffect(() => {
    if (query.data) setDraft(query.data);
  }, [query.data]);

  if (query.isLoading || !draft) return <p className="text-muted">Loading…</p>;
  if (query.isError)
    return (
      <div className="error">
        Failed to load STP discovery: {(query.error as Error).message}
      </div>
    );

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        setStatus(null);
        update.mutate(draft, {
          onSuccess: () =>
            setStatus({
              kind: 'success',
              message: 'STP polling schedule saved',
            }),
          onError: (err) =>
            setStatus({
              kind: 'error',
              message: `Failed to save STP schedule: ${(err as Error).message}`,
            }),
        });
      }}
    >
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem' }}>
        <label
          className="form-group"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.4rem',
          }}
        >
          <input
            type="checkbox"
            checked={draft.enabled}
            onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })}
          />
          <span>Enable scheduled STP polling</span>
        </label>
        <label
          className="form-group"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.4rem',
          }}
        >
          <input
            type="checkbox"
            checked={draft.all_vlans}
            onChange={(e) => setDraft({ ...draft, all_vlans: e.target.checked })}
          />
          <span>Poll all VLANs</span>
        </label>
        <div className="form-group" style={{ flex: '0 1 160px' }}>
          <label className="form-label">Interval (seconds)</label>
          <input
            type="number"
            min={60}
            className="form-input"
            value={draft.interval_seconds}
            onChange={(e) =>
              setDraft({ ...draft, interval_seconds: Number(e.target.value) })
            }
          />
        </div>
        <div className="form-group" style={{ flex: '0 1 140px' }}>
          <label className="form-label">VLAN ID</label>
          <input
            type="number"
            min={1}
            disabled={draft.all_vlans}
            className="form-input"
            value={draft.vlan_id}
            onChange={(e) => setDraft({ ...draft, vlan_id: Number(e.target.value) })}
          />
        </div>
        <div className="form-group" style={{ flex: '0 1 140px' }}>
          <label className="form-label">Max VLANs</label>
          <input
            type="number"
            min={1}
            className="form-input"
            value={draft.max_vlans}
            onChange={(e) =>
              setDraft({ ...draft, max_vlans: Number(e.target.value) })
            }
          />
        </div>
      </div>
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <button
          type="submit"
          className="btn btn-primary"
          disabled={update.isPending}
        >
          {update.isPending ? 'Saving…' : 'Save Schedule'}
        </button>
        <button
          type="button"
          className="btn btn-secondary"
          disabled={runNow.isPending}
          onClick={() => {
            setStatus(null);
            runNow.mutate(undefined, {
              onSuccess: (resp) => {
                const r = resp.result || {};
                if (r.enabled === false) {
                  setStatus({
                    kind: 'success',
                    message:
                      'Scheduled STP polling is disabled. Enable it or run Scan STP from Topology.',
                  });
                  return;
                }
                const kind = (r.errors ?? 0) > 0 ? 'error' : 'success';
                setStatus({
                  kind,
                  message: `STP polling complete: ${r.groups_scanned ?? 0} groups, ${r.ports_collected ?? 0} ports, ${r.errors ?? 0} errors`,
                });
              },
              onError: (err) =>
                setStatus({
                  kind: 'error',
                  message: `STP polling failed: ${(err as Error).message}`,
                }),
            });
          }}
        >
          {runNow.isPending ? 'Running…' : 'Run Now'}
        </button>
      </div>
      <StatusLine status={status} />
    </form>
  );
}

function StpRootPoliciesSection() {
  const groups = useInventoryGroupsList();
  const policies = useStpRootPolicies();
  const upsert = useUpsertStpRootPolicy();
  const remove = useDeleteStpRootPolicy();

  const [groupId, setGroupId] = useState<number | ''>('');
  const [vlanId, setVlanId] = useState<number>(1);
  const [bridgeId, setBridgeId] = useState('');
  const [hostname, setHostname] = useState('');
  const [enabled, setEnabled] = useState(true);
  const [status, setStatus] = useState<{ kind: 'success' | 'error'; message: string } | null>(null);

  useEffect(() => {
    if (groupId === '' && groups.data && groups.data.length > 0) {
      setGroupId(groups.data[0].id);
    }
  }, [groups.data, groupId]);

  return (
    <div>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          setStatus(null);
          if (!groupId || !bridgeId.trim()) {
            setStatus({
              kind: 'error',
              message: 'Group and expected root bridge ID are required.',
            });
            return;
          }
          upsert.mutate(
            {
              group_id: Number(groupId),
              vlan_id: vlanId,
              expected_root_bridge_id: bridgeId.trim(),
              expected_root_hostname: hostname.trim(),
              enabled,
            },
            {
              onSuccess: () => {
                setStatus({ kind: 'success', message: 'STP root policy saved' });
                setBridgeId('');
                setHostname('');
              },
              onError: (err) =>
                setStatus({
                  kind: 'error',
                  message: `Failed to save STP root policy: ${(err as Error).message}`,
                }),
            },
          );
        }}
      >
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem' }}>
          <div className="form-group" style={{ flex: '1 1 200px' }}>
            <label className="form-label">Group</label>
            <select
              className="form-select"
              value={groupId}
              onChange={(e) =>
                setGroupId(e.target.value ? Number(e.target.value) : '')
              }
            >
              {(groups.data || []).map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          </div>
          <div className="form-group" style={{ flex: '0 1 120px' }}>
            <label className="form-label">VLAN</label>
            <input
              type="number"
              min={1}
              className="form-input"
              value={vlanId}
              onChange={(e) => setVlanId(Number(e.target.value))}
            />
          </div>
          <div className="form-group" style={{ flex: '1 1 220px' }}>
            <label className="form-label">Expected Root Bridge ID</label>
            <input
              className="form-input"
              placeholder="32768.aabb.ccdd.eeff"
              value={bridgeId}
              onChange={(e) => setBridgeId(e.target.value)}
            />
          </div>
          <div className="form-group" style={{ flex: '1 1 180px' }}>
            <label className="form-label">Expected Hostname</label>
            <input
              className="form-input"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
            />
          </div>
          <label
            className="form-group"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.4rem',
            }}
          >
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            <span>Enabled</span>
          </label>
        </div>
        <div>
          <button
            type="submit"
            className="btn btn-primary btn-sm"
            disabled={upsert.isPending}
          >
            {upsert.isPending ? 'Saving…' : 'Save Policy'}
          </button>
        </div>
        <StatusLine status={status} />
      </form>

      <div style={{ marginTop: '1rem' }}>
        {policies.isLoading && <p className="text-muted">Loading policies…</p>}
        {policies.isError && (
          <div className="error">
            Failed to load STP root policies:{' '}
            {(policies.error as Error).message}
          </div>
        )}
        {policies.data?.policies?.length === 0 && (
          <p className="card-description">No STP root policies defined yet.</p>
        )}
        {(policies.data?.policies || []).map((p) => (
          <div
            key={p.id}
            className="card"
            style={{ marginBottom: '0.55rem', padding: '0.65rem 0.8rem' }}
          >
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'flex-start',
                gap: '0.75rem',
              }}
            >
              <div>
                <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>
                  {p.group_name || `Group ${p.group_id}`} · VLAN {p.vlan_id}
                </div>
                <div
                  style={{
                    fontFamily: 'monospace',
                    fontSize: '0.78rem',
                    marginTop: '0.15rem',
                  }}
                >
                  {p.expected_root_bridge_id}
                </div>
                {p.expected_root_hostname && (
                  <div className="card-description">
                    {p.expected_root_hostname}
                  </div>
                )}
              </div>
              <div
                style={{
                  display: 'flex',
                  gap: '0.4rem',
                  alignItems: 'center',
                }}
              >
                <span className={`badge ${p.enabled ? 'badge-success' : 'badge-info'}`}>
                  {p.enabled ? 'Enabled' : 'Disabled'}
                </span>
                <button
                  className="btn btn-sm"
                  style={{ color: 'var(--danger)' }}
                  onClick={() => {
                    if (!confirm('Delete this STP root policy?')) return;
                    remove.mutate(p.id, {
                      onError: (e) =>
                        alert(`Failed to delete: ${(e as Error).message}`),
                    });
                  }}
                >
                  Delete
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function SectionCard({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div
      className="card"
      style={{ padding: '1rem', marginBottom: '1.5rem' }}
    >
      <h3 style={{ margin: '0 0 0.75rem 0' }}>{title}</h3>
      {children}
    </div>
  );
}

export function DiscoveryTab() {
  return (
    <div>
      <SectionCard title="Topology Discovery">
        <TopologyDiscoverySection />
      </SectionCard>
      <SectionCard title="STP Polling">
        <StpDiscoverySection />
      </SectionCard>
      <SectionCard title="STP Root Policies">
        <StpRootPoliciesSection />
      </SectionCard>
    </div>
  );
}
