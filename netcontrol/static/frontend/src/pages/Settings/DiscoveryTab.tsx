import { useId, useState } from 'react';

import { groupLabel } from '@/api/inventory';
import { BusyButton } from '@/components/BusyButton';
import { DeleteButton } from '@/components/DeleteButton';
import { useDialogs } from '@/components/DialogProvider-context';
import {
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

import { CheckboxField, FormRow, NumberField, TextField } from './FormFields';
import { SaveBar } from './SaveBar';
import { SectionCard } from './SectionCard';
import { FormStatus, StatusLine } from './StatusLine';
import { useReportUnsaved } from './unsaved-context';
import { useSavedDraft } from './useSavedDraft';

function TopologyDiscoverySection() {
  const query = useTopologyDiscoveryConfig();
  const update = useUpdateTopologyDiscoveryConfig();
  const runNow = useRunTopologyDiscovery();
  const { draft, setDraft, dirty, discard, markSaved } = useSavedDraft(query.data);
  const [status, setStatus] = useState<FormStatus | null>(null);

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
          onSuccess: (saved) => {
            markSaved(saved);
            setStatus({
              kind: 'success',
              message: 'Topology discovery schedule saved',
            });
          },
          onError: (err) =>
            setStatus({
              kind: 'error',
              message: `Failed to save: ${(err as Error).message}`,
            }),
        });
      }}
    >
      <FormRow>
        <CheckboxField
          inRow
          label="Enable scheduled topology discovery"
          checked={draft.enabled}
          onChange={(v) => setDraft({ ...draft, enabled: v })}
        />
        <NumberField
          label="Interval (seconds)"
          value={draft.interval_seconds}
          min={60}
          flex="0 1 200px"
          onChange={(v) => setDraft({ ...draft, interval_seconds: v })}
        />
      </FormRow>
      <SaveBar
        name="Topology Discovery"
        dirty={dirty}
        busy={update.isPending}
        label="Save Schedule"
        status={status}
        onDiscard={discard}
      >
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
      </SaveBar>
    </form>
  );
}

function StpDiscoverySection() {
  const query = useStpDiscoveryConfig();
  const update = useUpdateStpDiscoveryConfig();
  const runNow = useRunStpDiscovery();
  const { draft, setDraft, dirty, discard, markSaved } = useSavedDraft(query.data);
  const [status, setStatus] = useState<FormStatus | null>(null);

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
          onSuccess: (saved) => {
            markSaved(saved);
            setStatus({
              kind: 'success',
              message: 'STP polling schedule saved',
            });
          },
          onError: (err) =>
            setStatus({
              kind: 'error',
              message: `Failed to save STP schedule: ${(err as Error).message}`,
            }),
        });
      }}
    >
      <FormRow>
        <CheckboxField
          inRow
          label="Enable scheduled STP polling"
          checked={draft.enabled}
          onChange={(v) => setDraft({ ...draft, enabled: v })}
        />
        <CheckboxField
          inRow
          label="Poll all VLANs"
          checked={draft.all_vlans}
          onChange={(v) => setDraft({ ...draft, all_vlans: v })}
        />
        <NumberField
          label="Interval (seconds)"
          value={draft.interval_seconds}
          min={60}
          flex="0 1 160px"
          onChange={(v) => setDraft({ ...draft, interval_seconds: v })}
        />
        <NumberField
          label="VLAN ID"
          value={draft.vlan_id}
          min={1}
          disabled={draft.all_vlans}
          onChange={(v) => setDraft({ ...draft, vlan_id: v })}
        />
        <NumberField
          label="Max VLANs"
          value={draft.max_vlans}
          min={1}
          onChange={(v) => setDraft({ ...draft, max_vlans: v })}
        />
      </FormRow>
      <SaveBar
        name="STP Polling"
        dirty={dirty}
        busy={update.isPending}
        label="Save Schedule"
        status={status}
        onDiscard={discard}
      >
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
      </SaveBar>
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
  const fid = useId();

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

  // A half-typed policy counts as unsaved; the group/VLAN pickers alone do not.
  useReportUnsaved('STP Root Policy', bridgeId.trim() !== '' || hostname.trim() !== '');

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
        <FormRow>
          <div className="form-group" style={{ flex: '1 1 200px' }}>
            <label className="form-label" htmlFor={`${fid}-group`}>Group</label>
            <select
              id={`${fid}-group`}
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
          <NumberField
            label="VLAN"
            value={vlanId}
            min={1}
            flex="0 1 120px"
            onChange={setVlanId}
          />
          <TextField
            label="Expected Root Bridge ID"
            value={bridgeId}
            placeholder="32768.aabb.ccdd.eeff"
            flex="1 1 220px"
            onChange={setBridgeId}
          />
          <TextField
            label="Expected Hostname"
            value={hostname}
            flex="1 1 180px"
            onChange={setHostname}
          />
          <CheckboxField
            inRow
            label="Enabled"
            checked={enabled}
            onChange={setEnabled}
          />
        </FormRow>
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
