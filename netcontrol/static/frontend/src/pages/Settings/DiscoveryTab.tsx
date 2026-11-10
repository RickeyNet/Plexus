import { useState } from 'react';

import { groupLabel } from '@/api/inventory';
import { BusyButton } from '@/components/BusyButton';
import { DeleteButton } from '@/components/DeleteButton';
import { useDialogs } from '@/components/DialogProvider-context';
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
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { SectionCard } from './SectionCard';
import { FormStatus, StatusLine } from './StatusLine';

function TopologyDiscoverySection() {
  const query = useTopologyDiscoveryConfig();
  const update = useUpdateTopologyDiscoveryConfig();
  const runNow = useRunTopologyDiscovery();
  const [draft, setDraft] = useState<TopologyDiscoveryConfig | null>(null);
  const [status, setStatus] = useState<FormStatus | null>(null);
  const [prevData, setPrevData] = useState(query.data);
  if (query.data !== prevData) {
    setPrevData(query.data);
    if (query.data) setDraft(query.data);
  }

  if (!draft) {
    if (query.isError)
      return (
        <QueryError what="topology discovery" query={query} />
      );
    return <LoadingState />;
  }

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
        <BusyButton
          type="submit"
          className="btn btn-primary"
          busy={update.isPending}
          busyLabel="Saving…"
        >
          Save Schedule
        </BusyButton>
        <BusyButton
          className="btn btn-secondary"
          busy={runNow.isPending}
          busyLabel="Running…"
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
          Run Now
        </BusyButton>
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
  const [status, setStatus] = useState<FormStatus | null>(null);
  const [prevData, setPrevData] = useState(query.data);
  if (query.data !== prevData) {
    setPrevData(query.data);
    if (query.data) setDraft(query.data);
  }

  if (!draft) {
    if (query.isError)
      return (
        <QueryError what="STP discovery" query={query} />
      );
    return <LoadingState />;
  }

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
        <BusyButton
          type="submit"
          className="btn btn-primary"
          busy={update.isPending}
          busyLabel="Saving…"
        >
          Save Schedule
        </BusyButton>
        <BusyButton
          className="btn btn-secondary"
          busy={runNow.isPending}
          busyLabel="Running…"
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
          Run Now
        </BusyButton>
      </div>
      <StatusLine status={status} />
    </form>
  );
}

function StpRootPoliciesSection() {
  const { confirm, alert } = useDialogs();
  const groups = useInventoryGroupsList();
  const policies = useStpRootPolicies();
  const upsert = useUpsertStpRootPolicy();
  const remove = useDeleteStpRootPolicy();
  const deleting = usePendingKeys<number>();

  const [groupId, setGroupId] = useState<number | ''>('');
  const [vlanId, setVlanId] = useState<number>(1);
  const [bridgeId, setBridgeId] = useState('');
  const [hostname, setHostname] = useState('');
  const [enabled, setEnabled] = useState(true);
  const [status, setStatus] = useState<FormStatus | null>(null);
  const [prevGroups, setPrevGroups] = useState(groups.data);
  if (groups.data !== prevGroups) {
    setPrevGroups(groups.data);
    if (groupId === '' && groups.data && groups.data.length > 0) {
      setGroupId(groups.data[0].id);
    }
  }

  return (
    <div>
      {groups.isError && !groups.data && (
        <QueryError what="inventory groups" query={groups} />
      )}
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
                  {groupLabel(g)}
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
          <BusyButton
            type="submit"
            className="btn btn-primary btn-sm"
            busy={upsert.isPending}
            busyLabel="Saving…"
          >
            Save Policy
          </BusyButton>
        </div>
        <StatusLine status={status} />
      </form>

      <div className="stack stack-sm" style={{ marginTop: 'var(--space-4)' }}>
        {policies.isLoading && <LoadingState text="Loading policies…" />}
        {policies.isError && !policies.data && (
          <QueryError what="STP root policies" query={policies} />
        )}
        {policies.data?.policies?.length === 0 && (
          <p className="card-description">No STP root policies defined yet.</p>
        )}
        {(policies.data?.policies || []).map((p) => (
          <div
            key={p.id}
            style={{ paddingTop: 'var(--space-3)', borderTop: '1px solid var(--border)' }}
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
                <DeleteButton
                  busy={deleting.isPending(p.id)}
                  onClick={async () => {
                    if (!(await confirm({
                      title: 'Delete STP root policy',
                      message: `Delete the STP root policy for ${p.group_name || `Group ${p.group_id}`} · VLAN ${p.vlan_id}?`,
                      confirmLabel: 'Delete',
                    }))) return;
                    await deleting.run(p.id, async () => {
                      try {
                        await remove.mutateAsync(p.id);
                      } catch (e) {
                        void alert({ message: `Failed to delete: ${(e as Error).message}`, variant: 'error' });
                      }
                    });
                  }}
                />
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export function DiscoveryTab() {
  return (
    <div className="stack">
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
