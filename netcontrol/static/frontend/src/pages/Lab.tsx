import { useMemo, useState, ReactNode } from 'react';

import { Modal } from '@/components/Modal';
import { TopologyCanvas } from '@/pages/TopologyCanvas';
import {
  LabDeviceSummary,
  useAddTopologyLink,
  useAddTopologyMember,
  useCreateDevice,
  useCreateEnvironment,
  useCreateTopology,
  useDeleteDevice,
  useDeleteEnvironment,
  useDeleteTopology,
  useDeployRuntime,
  useDeployTopology,
  useDestroyRuntime,
  useDestroyTopology,
  useDevice,
  useDriftRuns,
  useEnvironment,
  useEnvironments,
  useLatestDriftRun,
  useRefreshRuntime,
  useRefreshTopology,
  useRemoveTopologyLink,
  useRemoveTopologyMember,
  useRun,
  useRunDriftCheck,
  useRuns,
  useRuntimeEvents,
  useRuntimeStatus,
  useSimulate,
  useSimulateLive,
  useTopologies,
  useTopology,
} from '@/api/lab';

const PRE_STYLE: React.CSSProperties = {
  background: 'var(--bg-dark)',
  border: '1px solid var(--border)',
  color: 'var(--text)',
  padding: 12,
  maxHeight: 400,
  overflow: 'auto',
  fontSize: '0.8em',
  fontFamily: 'JetBrains Mono, ui-monospace, monospace',
  whiteSpace: 'pre',
  borderRadius: '0.375rem',
};

// ── Badge helpers ──────────────────────────────────────────────────────────

function Badge({
  variant,
  children,
}: {
  variant: 'success' | 'warning' | 'danger' | 'info' | 'secondary' | 'error';
  children: ReactNode;
}) {
  return <span className={`badge badge-${variant}`}>{children}</span>;
}

function riskBadge(level: string) {
  switch (level) {
    case 'critical':
      return <Badge variant="danger">{level}</Badge>;
    case 'high':
      return <Badge variant="error">{level}</Badge>;
    case 'medium':
      return <Badge variant="warning">{level}</Badge>;
    case 'low':
      return <Badge variant="success">{level}</Badge>;
    default:
      return <Badge variant="secondary">{level || 'unknown'}</Badge>;
  }
}

function driftBadge(status: string | undefined) {
  switch (status) {
    case 'in_sync':
      return <Badge variant="success">in sync</Badge>;
    case 'drifted':
      return <Badge variant="danger">drifted</Badge>;
    case 'missing_source':
      return <Badge variant="secondary">no source</Badge>;
    case 'error':
      return <Badge variant="warning">error</Badge>;
    case 'never_checked':
    case undefined:
    case '':
      return <Badge variant="secondary">not yet checked</Badge>;
    default:
      return <Badge variant="secondary">{status}</Badge>;
  }
}

function runtimeBadge(status: string | undefined, kind?: string) {
  if (!kind || kind === 'config_only') {
    return <Badge variant="secondary">offline</Badge>;
  }
  switch (status) {
    case 'running':
      return <Badge variant="success">running</Badge>;
    case 'provisioning':
      return <Badge variant="info">provisioning</Badge>;
    case 'stopped':
      return <Badge variant="secondary">stopped</Badge>;
    case 'destroyed':
      return <Badge variant="secondary">destroyed</Badge>;
    case 'error':
      return <Badge variant="danger">error</Badge>;
    default:
      return <Badge variant="secondary">{status || '—'}</Badge>;
  }
}

// ── Generic UI helpers ─────────────────────────────────────────────────────

function ErrorBox({ title, message }: { title: string; message: string }) {
  return (
    <div className="error">
      <strong>{title}:</strong> {message}
    </div>
  );
}

function Loading({ label }: { label?: string }) {
  return <div className="loading">{label ?? 'Loading…'}</div>;
}

function EmptyBox({ title, body }: { title: string; body: ReactNode }) {
  return (
    <div className="empty-state">
      <p style={{ fontWeight: 600, marginBottom: '0.5rem' }}>{title}</p>
      <p style={{ fontSize: '0.85em', opacity: 0.7 }}>{body}</p>
    </div>
  );
}

// ── Page ───────────────────────────────────────────────────────────────────

export function Lab() {
  const envs = useEnvironments();
  const [selectedEnvId, setSelectedEnvId] = useState<number | null>(null);
  const [selectedDeviceId, setSelectedDeviceId] = useState<number | null>(null);
  const [createEnvOpen, setCreateEnvOpen] = useState(false);

  const activeEnv = useEnvironment(selectedEnvId);

  return (
    <>
      <div className="page-header">
        <div>
          <h2>Lab / Digital Twin</h2>
          <p style={{ color: 'var(--text-light)', marginTop: '0.25rem', maxWidth: 720 }}>
            Safe sandbox for pre-production change testing. Clone a production
            device, apply proposed commands or templates against the simulated
            snapshot, review the diff and risk score, then promote a successful
            change to a real deployment.
          </p>
        </div>
        <button
          type="button"
          className="btn btn-primary"
          onClick={() => setCreateEnvOpen(true)}
        >
          New environment
        </button>
      </div>

      <div style={{ display: 'flex', gap: '1rem', alignItems: 'flex-start' }}>
        <div style={{ minWidth: 280 }}>
          <div className="glass-card card">
            <div className="card-title" style={{ marginBottom: '0.75rem' }}>
              Environments
            </div>
            {envs.isPending && <Loading />}
            {envs.error && (
              <ErrorBox title="Failed to load" message={(envs.error as Error).message} />
            )}
            {envs.data && envs.data.length === 0 && (
              <EmptyBox
                title="No environments yet"
                body="Create one to start testing config changes against simulated devices."
              />
            )}
            {envs.data?.map((e) => (
              <button
                key={e.id}
                type="button"
                onClick={() => {
                  setSelectedEnvId(e.id);
                  setSelectedDeviceId(null);
                }}
                style={{
                  display: 'block',
                  width: '100%',
                  textAlign: 'left',
                  cursor: 'pointer',
                  padding: '8px 12px',
                  borderRadius: 4,
                  marginBottom: 4,
                  border: '1px solid transparent',
                  background:
                    selectedEnvId === e.id ? 'var(--primary-soft)' : 'transparent',
                  color: 'var(--text)',
                }}
              >
                <strong>{e.name}</strong>
                <div style={{ fontSize: '0.85em', opacity: 0.7 }}>
                  {e.device_count ?? 0} device(s){e.shared ? ' · shared' : ''}
                </div>
              </button>
            ))}
          </div>
        </div>

        <div style={{ flex: 1, minWidth: 0 }}>
          {selectedEnvId === null ? (
            <div className="glass-card card">
              <EmptyBox
                title="Select an environment"
                body="Pick a lab environment on the left."
              />
            </div>
          ) : (
            <EnvironmentDetail
              envId={selectedEnvId}
              envQuery={activeEnv}
              selectedDeviceId={selectedDeviceId}
              onSelectDevice={setSelectedDeviceId}
              onEnvDeleted={() => {
                setSelectedEnvId(null);
                setSelectedDeviceId(null);
              }}
            />
          )}
        </div>
      </div>

      {createEnvOpen && (
        <CreateEnvironmentModal onClose={() => setCreateEnvOpen(false)} />
      )}
    </>
  );
}

// ── Create environment modal ───────────────────────────────────────────────

function CreateEnvironmentModal({ onClose }: { onClose: () => void }) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [shared, setShared] = useState(false);
  const create = useCreateEnvironment();

  return (
    <Modal isOpen onClose={onClose} title="Create lab environment">
      <div className="form-group">
        <label className="form-label" htmlFor="env-name">
          Name <span style={{ color: 'var(--danger)' }}>*</span>
        </label>
        <input
          id="env-name"
          className="form-input"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor="env-description">Description</label>
        <textarea
          id="env-description"
          className="form-input"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          rows={3}
        />
      </div>
      <div className="form-group">
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <input
            id="env-shared"
            type="checkbox"
            checked={shared}
            onChange={(e) => setShared(e.target.checked)}
          />
          Shared (visible to all operators)
        </label>
      </div>
      {create.error && (
        <ErrorBox title="Failed" message={(create.error as Error).message} />
      )}
      <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end', marginTop: '1rem' }}>
        <button
          type="button"
          className="btn btn-primary"
          disabled={!name.trim() || create.isPending}
          onClick={async () => {
            await create.mutateAsync({ name: name.trim(), description, shared });
            onClose();
          }}
        >
          Create
        </button>
        <button type="button" className="btn btn-ghost" onClick={onClose}>
          Cancel
        </button>
      </div>
    </Modal>
  );
}

// ── Environment detail ─────────────────────────────────────────────────────

interface EnvironmentDetailProps {
  envId: number;
  envQuery: ReturnType<typeof useEnvironment>;
  selectedDeviceId: number | null;
  onSelectDevice: (id: number | null) => void;
  onEnvDeleted: () => void;
}

function EnvironmentDetail({
  envId,
  envQuery,
  selectedDeviceId,
  onSelectDevice,
  onEnvDeleted,
}: EnvironmentDetailProps) {
  const deleteEnv = useDeleteEnvironment();
  const deleteDevice = useDeleteDevice(envId);
  const [createDeviceOpen, setCreateDeviceOpen] = useState(false);

  if (envQuery.isPending) return <Loading label="Loading environment…" />;
  if (envQuery.error)
    return (
      <ErrorBox
        title="Failed to load environment"
        message={(envQuery.error as Error).message}
      />
    );
  if (!envQuery.data) return null;

  const env = envQuery.data;
  const devices: LabDeviceSummary[] = env.devices ?? [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div className="glass-card card">
        <div className="card-title">{env.name}</div>
        <p style={{ color: 'var(--text-light)' }}>
          {env.description || <em>No description.</em>}
        </p>
        <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => setCreateDeviceOpen(true)}
          >
            Add lab device
          </button>
          <button
            type="button"
            className="btn btn-danger"
            onClick={async () => {
              if (
                !confirm(
                  `Delete environment "${env.name}"? This removes all devices and runs.`,
                )
              )
                return;
              await deleteEnv.mutateAsync(env.id);
              onEnvDeleted();
            }}
          >
            Delete environment
          </button>
        </div>
      </div>

      <div className="glass-card card">
        <div className="card-title">Devices ({devices.length})</div>
        {devices.length === 0 ? (
          <EmptyBox
            title="No devices in this environment"
            body="Add a blank device or clone one from inventory to start simulating changes."
          />
        ) : (
          <table className="data-table" style={{ width: '100%' }}>
            <thead>
              <tr>
                <th>Hostname</th>
                <th>IP</th>
                <th>Type</th>
                <th>Runtime</th>
                <th>Config</th>
                <th>Runs</th>
                <th>Source</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => {
                const selected = selectedDeviceId === d.id;
                return (
                  <tr
                    key={d.id}
                    style={{
                      cursor: 'pointer',
                      background: selected ? 'var(--primary-soft)' : undefined,
                    }}
                    onClick={() => onSelectDevice(d.id)}
                  >
                    <td>{d.hostname}</td>
                    <td>{d.runtime_mgmt_address || d.ip_address || '—'}</td>
                    <td>{d.device_type}</td>
                    <td>{runtimeBadge(d.runtime_status, d.runtime_kind)}</td>
                    <td>{d.config_size} B</td>
                    <td>{d.run_count}</td>
                    <td>{d.source_host_id ? `#${d.source_host_id}` : '—'}</td>
                    <td onClick={(e) => e.stopPropagation()}>
                      <button
                        type="button"
                        className="btn btn-sm btn-danger"
                        onClick={async () => {
                          if (!confirm(`Delete device "${d.hostname}"?`)) return;
                          if (selectedDeviceId === d.id) onSelectDevice(null);
                          await deleteDevice.mutateAsync(d.id);
                        }}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {selectedDeviceId !== null && <DevicePanel deviceId={selectedDeviceId} />}

      <TopologiesCard envId={envId} devices={devices} />

      {createDeviceOpen && (
        <CreateDeviceModal envId={envId} onClose={() => setCreateDeviceOpen(false)} />
      )}
    </div>
  );
}

// ── Create device modal ────────────────────────────────────────────────────

function CreateDeviceModal({ envId, onClose }: { envId: number; onClose: () => void }) {
  const [hostname, setHostname] = useState('');
  const [ip, setIp] = useState('');
  const [deviceType, setDeviceType] = useState('cisco_ios');
  const [config, setConfig] = useState('');
  const [cloneHostId, setCloneHostId] = useState('');
  const create = useCreateDevice(envId);

  return (
    <Modal isOpen onClose={onClose} title="Add lab device">
      <div className="form-group">
        <label className="form-label" htmlFor="dev-name">
          Hostname <span style={{ color: 'var(--danger)' }}>*</span>
        </label>
        <input
          id="dev-name"
          className="form-input"
          value={hostname}
          onChange={(e) => setHostname(e.target.value)}
        />
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor="dev-ip">IP address</label>
        <input
          id="dev-ip"
          className="form-input"
          value={ip}
          onChange={(e) => setIp(e.target.value)}
        />
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor="dev-type">Device type</label>
        <input
          id="dev-type"
          className="form-input"
          value={deviceType}
          onChange={(e) => setDeviceType(e.target.value)}
        />
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor="dev-config">
          Initial running config (optional)
        </label>
        <textarea
          id="dev-config"
          className="form-input"
          value={config}
          onChange={(e) => setConfig(e.target.value)}
          rows={6}
          placeholder="Paste a known-good config or leave empty."
        />
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor="dev-clone">
          Or clone from inventory host ID
        </label>
        <input
          id="dev-clone"
          className="form-input"
          value={cloneHostId}
          onChange={(e) => setCloneHostId(e.target.value)}
          placeholder="e.g. 42"
        />
      </div>
      {create.error && (
        <ErrorBox title="Failed" message={(create.error as Error).message} />
      )}
      <div
        style={{
          display: 'flex',
          gap: '0.5rem',
          justifyContent: 'flex-end',
          marginTop: '1rem',
          flexWrap: 'wrap',
        }}
      >
        <button
          type="button"
          className="btn btn-primary"
          disabled={!hostname.trim() || create.isPending}
          onClick={async () => {
            await create.mutateAsync({
              hostname: hostname.trim(),
              ip_address: ip,
              device_type: deviceType || 'cisco_ios',
              running_config: config,
            });
            onClose();
          }}
        >
          Create blank
        </button>
        <button
          type="button"
          className="btn btn-secondary"
          disabled={!cloneHostId || Number.isNaN(Number(cloneHostId))}
          onClick={async () => {
            const res = await fetch(`/api/lab/environments/${envId}/clone-host`, {
              method: 'POST',
              credentials: 'include',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ host_id: Number(cloneHostId) }),
            });
            if (!res.ok) {
              alert(`Clone failed: ${res.status}`);
              return;
            }
            onClose();
          }}
        >
          Clone from inventory host ID
        </button>
        <button type="button" className="btn btn-ghost" onClick={onClose}>
          Cancel
        </button>
      </div>
    </Modal>
  );
}

// ── Device panel ───────────────────────────────────────────────────────────

function DevicePanel({ deviceId }: { deviceId: number }) {
  const device = useDevice(deviceId);
  const runs = useRuns(deviceId);
  const [commandsText, setCommandsText] = useState('');
  const [applyToDevice, setApplyToDevice] = useState(false);
  const [liveMode, setLiveMode] = useState(false);
  const simulate = useSimulate(deviceId);
  const simulateLive = useSimulateLive(deviceId);
  const [openRunId, setOpenRunId] = useState<number | null>(null);

  const isRuntimeRunning = device.data?.runtime_status === 'running';
  const lastResult = liveMode ? simulateLive.data : simulate.data;
  const lastError = liveMode
    ? (simulateLive.error as Error | null)
    : (simulate.error as Error | null);
  const isPending = liveMode ? simulateLive.isPending : simulate.isPending;

  const commandList = useMemo(
    () =>
      commandsText
        .split('\n')
        .map((s) => s.trim())
        .filter((s) => s && !s.startsWith('#') && !s.startsWith('!')),
    [commandsText],
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <RuntimeCard deviceId={deviceId} />

      <div className="glass-card card">
        <div className="card-title">Simulate change against device #{deviceId}</div>
        <div className="form-group">
          <label className="form-label" htmlFor="sim-cmds">
            Proposed commands (one per line)
          </label>
          <textarea
            id="sim-cmds"
            className="form-input"
            value={commandsText}
            onChange={(e) => setCommandsText(e.target.value)}
            rows={6}
            placeholder={'interface GigabitEthernet0/1\n description uplink\n no shutdown'}
          />
        </div>
        <div className="form-group">
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <input
              id="sim-live"
              type="checkbox"
              checked={liveMode}
              disabled={!isRuntimeRunning}
              onChange={(e) => setLiveMode(e.target.checked)}
            />
            Live mode (push to running containerlab device)
          </label>
          {!isRuntimeRunning && (
            <div style={{ fontSize: '0.85em', color: 'var(--text-muted)', marginTop: 4 }}>
              Deploy a containerlab runtime above to enable live mode.
            </div>
          )}
        </div>
        {!liveMode && (
          <div className="form-group">
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <input
                id="sim-apply"
                type="checkbox"
                checked={applyToDevice}
                onChange={(e) => setApplyToDevice(e.target.checked)}
              />
              Persist resulting config back to lab device snapshot
            </label>
          </div>
        )}
        <button
          type="button"
          className="btn btn-primary"
          disabled={commandList.length === 0 || isPending}
          onClick={() => {
            if (liveMode) {
              simulateLive.mutate({ proposed_commands: commandList });
            } else {
              simulate.mutate({
                proposed_commands: commandList,
                apply_to_device: applyToDevice,
              });
            }
          }}
        >
          {liveMode ? 'Run live simulation' : 'Run simulation'}
        </button>
        {lastError && (
          <div style={{ marginTop: '1rem' }}>
            <ErrorBox title="Simulation failed" message={lastError.message} />
          </div>
        )}
      </div>

      {lastResult && (
        <div className="glass-card card">
          <div className="card-title">
            Last result — {riskBadge(lastResult.risk_level)} (score{' '}
            {lastResult.risk_score})
          </div>
          <p>
            +{lastResult.diff_added} / −{lastResult.diff_removed} lines
            {lastResult.affected_areas.length > 0 && (
              <> · areas: {lastResult.affected_areas.join(', ')}</>
            )}
            {liveMode && <> · <strong>live</strong></>}
          </p>
          <pre style={PRE_STYLE}>{lastResult.diff_text || '(no diff)'}</pre>
          {liveMode && 'push_output' in lastResult && lastResult.push_output && (
            <>
              <h4 style={{ marginTop: '1rem' }}>Device push output</h4>
              <pre style={{ ...PRE_STYLE, maxHeight: 200 }}>
                {lastResult.push_output}
              </pre>
            </>
          )}
        </div>
      )}

      <DriftCard deviceId={deviceId} />

      <div className="glass-card card">
        <div className="card-title">Run history</div>
        {runs.isPending && <Loading />}
        {runs.data && runs.data.length === 0 && (
          <EmptyBox
            title="No runs yet"
            body="Submit commands above to record a simulation run."
          />
        )}
        {runs.data && runs.data.length > 0 && (
          <table className="data-table" style={{ width: '100%' }}>
            <thead>
              <tr>
                <th>ID</th>
                <th>When</th>
                <th>By</th>
                <th>Risk</th>
                <th>+/−</th>
                <th>Status</th>
                <th>Promoted</th>
              </tr>
            </thead>
            <tbody>
              {runs.data.map((r) => (
                <tr
                  key={r.id}
                  onClick={() => setOpenRunId(r.id)}
                  style={{ cursor: 'pointer' }}
                >
                  <td>{r.id}</td>
                  <td>{r.created_at}</td>
                  <td>{r.submitted_by || '—'}</td>
                  <td>{riskBadge(r.risk_level)}</td>
                  <td>+{r.diff_added}/−{r.diff_removed}</td>
                  <td>{r.status}</td>
                  <td>
                    {r.promoted_deployment_id ? `#${r.promoted_deployment_id}` : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {openRunId !== null && (
        <RunDetailModal runId={openRunId} onClose={() => setOpenRunId(null)} />
      )}
    </div>
  );
}

// ── Run detail modal ───────────────────────────────────────────────────────

function RunDetailModal({ runId, onClose }: { runId: number; onClose: () => void }) {
  const run = useRun(runId);
  return (
    <Modal isOpen onClose={onClose} title={`Lab run #${runId}`} size="large">
      {run.isPending && <Loading />}
      {run.error && (
        <ErrorBox title="Failed" message={(run.error as Error).message} />
      )}
      {run.data && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <p>
            {riskBadge(run.data.risk_level)} score {run.data.risk_score} · status{' '}
            <strong>{run.data.status}</strong> · +{run.data.diff_added}/−
            {run.data.diff_removed} lines
          </p>
          <div>
            <h4 style={{ marginBottom: '0.5rem' }}>Diff</h4>
            <pre style={{ ...PRE_STYLE, maxHeight: 320 }}>
              {run.data.diff_text || '(no diff)'}
            </pre>
          </div>
          <div>
            <h4 style={{ marginBottom: '0.5rem' }}>Commands</h4>
            <pre style={{ ...PRE_STYLE, maxHeight: 200 }}>
              {(run.data.commands || []).join('\n') || '(none)'}
            </pre>
          </div>
        </div>
      )}
    </Modal>
  );
}

// ── Phase B-1: containerlab runtime card ──────────────────────────────────

function RuntimeCard({ deviceId }: { deviceId: number }) {
  const status = useRuntimeStatus();
  const device = useDevice(deviceId);
  const events = useRuntimeEvents(deviceId);
  const deploy = useDeployRuntime(deviceId);
  const destroy = useDestroyRuntime(deviceId);
  const refresh = useRefreshRuntime(deviceId);

  const [nodeKind, setNodeKind] = useState('linux');
  const [image, setImage] = useState('');
  const [credentialId, setCredentialId] = useState('');

  const allowedKinds = status.data?.allowed_node_kinds ?? [];
  const dev = device.data;
  const runtimeKind = dev?.runtime_kind ?? 'config_only';
  const runtimeStatus = dev?.runtime_status ?? '';
  const isRunning = runtimeStatus === 'running';
  const isProvisioning = runtimeStatus === 'provisioning';
  const hasRuntime = runtimeKind === 'containerlab' && runtimeStatus !== 'destroyed';

  return (
    <div className="glass-card card">
      <div className="card-title">
        Containerlab runtime · {runtimeBadge(runtimeStatus, runtimeKind)}
      </div>

      {status.isPending && <Loading label="Checking runtime…" />}
      {status.data && !status.data.available && (
        <div style={{
          background: 'rgba(245, 158, 11, 0.1)',
          color: 'var(--warning)',
          border: '1px solid rgba(245, 158, 11, 0.25)',
          padding: '0.75rem 1rem',
          borderRadius: '0.375rem',
          marginBottom: '1rem',
        }}>
          <strong>containerlab unavailable on the Plexus host.</strong>{' '}
          {status.data.reason || 'See server logs for details.'} Lab devices
          still work in offline (config-only) mode; live deploy is disabled.
        </div>
      )}

      {dev && hasRuntime && (
        <p>
          <strong>Node kind:</strong> {dev.runtime_node_kind || '—'} ·{' '}
          <strong>Image:</strong> {dev.runtime_image || '—'} ·{' '}
          <strong>Mgmt IP:</strong> {dev.runtime_mgmt_address || '—'}{' '}
          {dev.runtime_lab_name && (
            <>
              · <strong>Lab:</strong> {dev.runtime_lab_name}
            </>
          )}
        </p>
      )}
      {dev?.runtime_error && (
        <ErrorBox title="Runtime error" message={dev.runtime_error} />
      )}

      {!isRunning && !isProvisioning && (
        <div style={{ marginTop: '1rem' }}>
          <div className="form-group">
            <label className="form-label" htmlFor="rt-kind">Node kind</label>
            <select
              id="rt-kind"
              className="form-select"
              value={nodeKind}
              onChange={(e) => setNodeKind(e.target.value)}
              style={{ minWidth: 200 }}
            >
              {allowedKinds.length === 0 && <option value="linux">linux</option>}
              {allowedKinds.map((k) => (
                <option key={k} value={k}>{k}</option>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="rt-image">Container image</label>
            <input
              id="rt-image"
              className="form-input"
              value={image}
              onChange={(e) => setImage(e.target.value)}
              placeholder="e.g. frrouting/frr:latest, ceos:4.30.0F, ghcr.io/nokia/srlinux:latest"
            />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="rt-cred">
              SSH credential ID (for live push)
            </label>
            <input
              id="rt-cred"
              className="form-input"
              value={credentialId}
              onChange={(e) => setCredentialId(e.target.value)}
              placeholder="optional — required only for live simulate"
            />
          </div>
          <button
            type="button"
            className="btn btn-primary"
            disabled={
              !status.data?.available || !image.trim() || deploy.isPending
            }
            onClick={() =>
              deploy.mutate({
                node_kind: nodeKind,
                image: image.trim(),
                credential_id: credentialId ? Number(credentialId) : null,
              })
            }
          >
            Deploy live
          </button>
          {deploy.error && (
            <div style={{ marginTop: '0.75rem' }}>
              <ErrorBox title="Deploy failed" message={(deploy.error as Error).message} />
            </div>
          )}
        </div>
      )}

      {(isRunning || isProvisioning || hasRuntime) && (
        <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={refresh.isPending}
            onClick={() => refresh.mutate()}
          >
            Refresh status
          </button>
          <button
            type="button"
            className="btn btn-danger"
            disabled={destroy.isPending}
            onClick={async () => {
              if (!confirm('Destroy the containerlab runtime for this device?')) return;
              await destroy.mutateAsync();
            }}
          >
            Destroy runtime
          </button>
        </div>
      )}

      {events.data && events.data.length > 0 && (
        <details style={{ marginTop: 16 }}>
          <summary style={{ cursor: 'pointer', color: 'var(--text-light)' }}>
            Runtime event log
          </summary>
          <table className="data-table" style={{ width: '100%', marginTop: 8 }}>
            <thead>
              <tr>
                <th>When</th>
                <th>Action</th>
                <th>Status</th>
                <th>By</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {events.data.map((e) => (
                <tr key={e.id}>
                  <td>{e.created_at}</td>
                  <td>{e.action}</td>
                  <td>{e.status}</td>
                  <td>{e.actor || '—'}</td>
                  <td>{e.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}
    </div>
  );
}

// ── Phase B-2: multi-device topologies ─────────────────────────────────────

function TopologiesCard({
  envId,
  devices,
}: {
  envId: number;
  devices: LabDeviceSummary[];
}) {
  const list = useTopologies(envId);
  const create = useCreateTopology(envId);
  const remove = useDeleteTopology(envId);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [mgmt, setMgmt] = useState('');
  const [openId, setOpenId] = useState<number | null>(null);

  return (
    <div className="glass-card card">
      <div className="card-title">Topologies (multi-device)</div>

      <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-end', flexWrap: 'wrap' }}>
        <div className="form-group" style={{ flex: 1, minWidth: 180, marginBottom: 0 }}>
          <label className="form-label" htmlFor="topo-name">New topology name</label>
          <input
            id="topo-name"
            className="form-input"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. dual-core-test"
          />
        </div>
        <div className="form-group" style={{ flex: 1, minWidth: 180, marginBottom: 0 }}>
          <label className="form-label" htmlFor="topo-desc">Description</label>
          <input
            id="topo-desc"
            className="form-input"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </div>
        <div className="form-group" style={{ minWidth: 180, marginBottom: 0 }}>
          <label className="form-label" htmlFor="topo-mgmt">Mgmt subnet (optional)</label>
          <input
            id="topo-mgmt"
            className="form-input"
            value={mgmt}
            onChange={(e) => setMgmt(e.target.value)}
            placeholder="e.g. 172.20.30.0/24"
          />
        </div>
        <button
          type="button"
          className="btn btn-primary"
          disabled={!name.trim() || create.isPending}
          onClick={async () => {
            await create.mutateAsync({
              name: name.trim(),
              description,
              mgmt_subnet: mgmt,
            });
            setName('');
            setDescription('');
            setMgmt('');
          }}
        >
          Create
        </button>
      </div>

      {create.error && (
        <div style={{ marginTop: '0.75rem' }}>
          <ErrorBox title="Failed" message={(create.error as Error).message} />
        </div>
      )}

      {list.isPending && <Loading />}
      {list.data && list.data.length === 0 && (
        <EmptyBox
          title="No topologies yet"
          body="Create one above, then add member devices and links."
        />
      )}
      {list.data && list.data.length > 0 && (
        <table className="data-table" style={{ width: '100%', marginTop: 12 }}>
          <thead>
            <tr>
              <th>Name</th>
              <th>Devices</th>
              <th>Links</th>
              <th>Status</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {list.data.map((t) => (
              <tr
                key={t.id}
                style={{
                  cursor: 'pointer',
                  background: openId === t.id ? 'var(--primary-soft)' : undefined,
                }}
                onClick={() => setOpenId(openId === t.id ? null : t.id)}
              >
                <td>{t.name}</td>
                <td>{t.device_count ?? 0}</td>
                <td>{t.link_count ?? 0}</td>
                <td>{runtimeBadge(t.status, 'containerlab')}</td>
                <td onClick={(e) => e.stopPropagation()}>
                  <button
                    type="button"
                    className="btn btn-sm btn-danger"
                    disabled={t.status === 'running'}
                    onClick={async () => {
                      if (!confirm(`Delete topology "${t.name}"?`)) return;
                      if (openId === t.id) setOpenId(null);
                      await remove.mutateAsync(t.id);
                    }}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {openId !== null && (
        <div style={{ marginTop: 16 }}>
          <TopologyEditor topologyId={openId} envDevices={devices} />
        </div>
      )}
    </div>
  );
}

function TopologyEditor({
  topologyId,
  envDevices,
}: {
  topologyId: number;
  envDevices: LabDeviceSummary[];
}) {
  const topo = useTopology(topologyId);
  const addMember = useAddTopologyMember(topologyId);
  const removeMember = useRemoveTopologyMember(topologyId);
  const addLink = useAddTopologyLink(topologyId);
  const removeLink = useRemoveTopologyLink(topologyId);
  const deploy = useDeployTopology(topologyId);
  const destroy = useDestroyTopology(topologyId);
  const refresh = useRefreshTopology(topologyId);

  const [memberPick, setMemberPick] = useState('');
  const [linkA, setLinkA] = useState('');
  const [linkAEp, setLinkAEp] = useState('eth1');
  const [linkB, setLinkB] = useState('');
  const [linkBEp, setLinkBEp] = useState('eth1');
  const [viewMode, setViewMode] = useState<'list' | 'canvas'>('list');
  const [pendingProposal, setPendingProposal] = useState<
    { a_device_id: number; b_device_id: number } | null
  >(null);
  const [proposalA, setProposalA] = useState('eth1');
  const [proposalB, setProposalB] = useState('eth1');

  if (topo.isPending) return <Loading label="Loading topology…" />;
  if (topo.error)
    return <ErrorBox title="Failed" message={(topo.error as Error).message} />;
  if (!topo.data) return null;

  const t = topo.data;
  const isRunning = t.status === 'running';
  const memberIds = new Set(t.devices.map((d) => d.id));
  const candidates = envDevices.filter((d) => !memberIds.has(d.id));

  return (
    <div className="card" style={{ background: 'transparent', border: '1px solid var(--border)' }}>
      <div className="card-title">
        Editing: {t.name} · {runtimeBadge(t.status, 'containerlab')}
      </div>
      {t.error && <ErrorBox title="Topology error" message={t.error} />}

      <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
        <button
          type="button"
          className="btn btn-primary"
          disabled={isRunning || deploy.isPending || t.devices.length === 0}
          onClick={() => deploy.mutate()}
        >
          Deploy topology
        </button>
        <button
          type="button"
          className="btn btn-secondary"
          disabled={refresh.isPending}
          onClick={() => refresh.mutate()}
        >
          Refresh
        </button>
        <button
          type="button"
          className="btn btn-danger"
          disabled={destroy.isPending || t.status === 'destroyed' || t.status === ''}
          onClick={async () => {
            if (!confirm('Destroy topology?')) return;
            await destroy.mutateAsync();
          }}
        >
          Destroy topology
        </button>
      </div>
      {deploy.error && (
        <ErrorBox title="Deploy failed" message={(deploy.error as Error).message} />
      )}

      <div style={{ display: 'flex', gap: 4, margin: '8px 0' }}>
        <button
          type="button"
          className={`btn btn-sm ${viewMode === 'list' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setViewMode('list')}
        >
          List
        </button>
        <button
          type="button"
          className={`btn btn-sm ${viewMode === 'canvas' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setViewMode('canvas')}
        >
          Canvas
        </button>
      </div>

      {viewMode === 'canvas' && (
        <div style={{ marginBottom: 16 }}>
          <TopologyCanvas
            devices={t.devices}
            links={t.links}
            onProposeLink={
              isRunning
                ? undefined
                : (proposed) => {
                    setPendingProposal(proposed);
                    setProposalA('eth1');
                    setProposalB('eth1');
                  }
            }
          />
          {pendingProposal && (
            <div
              style={{
                marginTop: 8,
                padding: 12,
                border: '1px solid var(--primary)',
                borderRadius: 4,
                background: 'var(--primary-soft)',
              }}
            >
              <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-end', flexWrap: 'wrap' }}>
                <div style={{ flex: 1, minWidth: 200 }}>
                  <p>
                    New link:{' '}
                    <strong>
                      {t.devices.find((d) => d.id === pendingProposal.a_device_id)?.hostname}
                    </strong>{' '}
                    ↔{' '}
                    <strong>
                      {t.devices.find((d) => d.id === pendingProposal.b_device_id)?.hostname}
                    </strong>
                  </p>
                </div>
                <div className="form-group" style={{ marginBottom: 0 }}>
                  <label className="form-label" htmlFor="prop-a-ep">A endpoint</label>
                  <input
                    id="prop-a-ep"
                    className="form-input"
                    value={proposalA}
                    onChange={(e) => setProposalA(e.target.value)}
                  />
                </div>
                <div className="form-group" style={{ marginBottom: 0 }}>
                  <label className="form-label" htmlFor="prop-b-ep">B endpoint</label>
                  <input
                    id="prop-b-ep"
                    className="form-input"
                    value={proposalB}
                    onChange={(e) => setProposalB(e.target.value)}
                  />
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button
                    type="button"
                    className="btn btn-primary"
                    disabled={!proposalA.trim() || !proposalB.trim() || addLink.isPending}
                    onClick={async () => {
                      await addLink.mutateAsync({
                        a_device_id: pendingProposal.a_device_id,
                        a_endpoint: proposalA.trim(),
                        b_device_id: pendingProposal.b_device_id,
                        b_endpoint: proposalB.trim(),
                      });
                      setPendingProposal(null);
                    }}
                  >
                    Create link
                  </button>
                  <button
                    type="button"
                    className="btn btn-ghost"
                    onClick={() => setPendingProposal(null)}
                  >
                    Cancel
                  </button>
                </div>
              </div>
              {addLink.error && (
                <div style={{ marginTop: '0.5rem' }}>
                  <ErrorBox
                    title="Add link failed"
                    message={(addLink.error as Error).message}
                  />
                </div>
              )}
            </div>
          )}
        </div>
      )}

      <h4 style={{ marginTop: '1rem', marginBottom: '0.5rem' }}>
        Members ({t.devices.length})
      </h4>
      <table className="data-table" style={{ width: '100%', marginBottom: 12 }}>
        <thead>
          <tr>
            <th>Hostname</th>
            <th>Kind</th>
            <th>Image</th>
            <th>Mgmt IP</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {t.devices.map((d) => (
            <tr key={d.id}>
              <td>{d.hostname}</td>
              <td>{d.runtime_node_kind || '—'}</td>
              <td>{d.runtime_image || '—'}</td>
              <td>{d.runtime_mgmt_address || '—'}</td>
              <td>
                <button
                  type="button"
                  className="btn btn-sm btn-danger"
                  disabled={isRunning}
                  onClick={() => removeMember.mutate(d.id)}
                >
                  Remove
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {!isRunning && (
        <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
          <select
            className="form-select"
            value={memberPick}
            onChange={(e) => setMemberPick(e.target.value)}
            style={{ minWidth: 200 }}
          >
            <option value="">— select a device to add —</option>
            {candidates.map((d) => (
              <option key={d.id} value={String(d.id)}>
                {d.hostname} ({d.runtime_node_kind || 'no kind'})
              </option>
            ))}
          </select>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={!memberPick || addMember.isPending}
            onClick={async () => {
              await addMember.mutateAsync({ device_id: Number(memberPick) });
              setMemberPick('');
            }}
          >
            Add member
          </button>
          {addMember.error && (
            <div style={{ alignSelf: 'center' }}>
              <ErrorBox title="Add failed" message={(addMember.error as Error).message} />
            </div>
          )}
        </div>
      )}

      <h4 style={{ marginTop: '1rem', marginBottom: '0.5rem' }}>
        Links ({t.links.length})
      </h4>
      <table className="data-table" style={{ width: '100%', marginBottom: 12 }}>
        <thead>
          <tr>
            <th>A device</th>
            <th>A endpoint</th>
            <th>B device</th>
            <th>B endpoint</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {t.links.map((l) => {
            const a = t.devices.find((d) => d.id === l.a_device_id);
            const b = t.devices.find((d) => d.id === l.b_device_id);
            return (
              <tr key={l.id}>
                <td>{a?.hostname ?? `#${l.a_device_id}`}</td>
                <td>{l.a_endpoint}</td>
                <td>{b?.hostname ?? `#${l.b_device_id}`}</td>
                <td>{l.b_endpoint}</td>
                <td>
                  <button
                    type="button"
                    className="btn btn-sm btn-danger"
                    disabled={isRunning}
                    onClick={() => removeLink.mutate(l.id)}
                  >
                    Remove
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>

      {!isRunning && t.devices.length >= 2 && (
        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-label" htmlFor="link-a">A device</label>
            <select
              id="link-a"
              className="form-select"
              value={linkA}
              onChange={(e) => setLinkA(e.target.value)}
              style={{ minWidth: 160 }}
            >
              <option value="">—</option>
              {t.devices.map((d) => (
                <option key={d.id} value={String(d.id)}>
                  {d.hostname}
                </option>
              ))}
            </select>
          </div>
          <div className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-label" htmlFor="link-a-ep">A endpoint</label>
            <input
              id="link-a-ep"
              className="form-input"
              value={linkAEp}
              onChange={(e) => setLinkAEp(e.target.value)}
            />
          </div>
          <div className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-label" htmlFor="link-b">B device</label>
            <select
              id="link-b"
              className="form-select"
              value={linkB}
              onChange={(e) => setLinkB(e.target.value)}
              style={{ minWidth: 160 }}
            >
              <option value="">—</option>
              {t.devices.map((d) => (
                <option key={d.id} value={String(d.id)}>
                  {d.hostname}
                </option>
              ))}
            </select>
          </div>
          <div className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-label" htmlFor="link-b-ep">B endpoint</label>
            <input
              id="link-b-ep"
              className="form-input"
              value={linkBEp}
              onChange={(e) => setLinkBEp(e.target.value)}
            />
          </div>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={
              !linkA ||
              !linkB ||
              linkA === linkB ||
              !linkAEp.trim() ||
              !linkBEp.trim() ||
              addLink.isPending
            }
            onClick={async () => {
              await addLink.mutateAsync({
                a_device_id: Number(linkA),
                a_endpoint: linkAEp.trim(),
                b_device_id: Number(linkB),
                b_endpoint: linkBEp.trim(),
              });
              setLinkAEp('eth1');
              setLinkBEp('eth1');
            }}
          >
            Add link
          </button>
        </div>
      )}
      {addLink.error && (
        <div style={{ marginTop: '0.75rem' }}>
          <ErrorBox title="Add link failed" message={(addLink.error as Error).message} />
        </div>
      )}
    </div>
  );
}

// ── Phase B-3a: drift-from-twin card ───────────────────────────────────────

function DriftCard({ deviceId }: { deviceId: number }) {
  const latest = useLatestDriftRun(deviceId);
  const runs = useDriftRuns(deviceId);
  const check = useRunDriftCheck(deviceId);
  const device = useDevice(deviceId);

  const sourceHostId = device.data?.source_host_id ?? null;
  const latestStatus = (latest.data && 'status' in latest.data
    ? latest.data.status
    : 'never_checked') as
    | 'in_sync'
    | 'drifted'
    | 'missing_source'
    | 'error'
    | 'never_checked';

  return (
    <div className="glass-card card">
      <div className="card-title">
        Drift from production · {driftBadge(latestStatus)}
      </div>

      {sourceHostId === null && (
        <div style={{
          background: 'var(--primary-soft)',
          color: 'var(--primary-light)',
          border: '1px solid var(--primary-soft-strong)',
          padding: '0.75rem 1rem',
          borderRadius: '0.375rem',
          marginBottom: '1rem',
        }}>
          <strong>Twin has no source host.</strong> This lab device wasn't
          cloned from inventory, so there's no production config to compare
          against. Drift checks only run when <code>source_host_id</code> is set.
        </div>
      )}

      {sourceHostId !== null && latest.data && 'diff_added' in latest.data && (
        <p>
          Last checked: <strong>{latest.data.checked_at}</strong> · +
          {latest.data.diff_added}/−{latest.data.diff_removed} lines · actor:{' '}
          {latest.data.actor || '—'}
          {latest.data.error && (
            <>
              {' · '}
              <em>{latest.data.error}</em>
            </>
          )}
        </p>
      )}

      <div style={{ display: 'flex', gap: 8, margin: '12px 0' }}>
        <button
          type="button"
          className="btn btn-primary"
          disabled={check.isPending || sourceHostId === null}
          onClick={() => check.mutate()}
        >
          Run drift check
        </button>
      </div>
      {check.error && (
        <ErrorBox title="Drift check failed" message={(check.error as Error).message} />
      )}

      {runs.data && runs.data.length > 0 && (
        <details>
          <summary style={{ cursor: 'pointer', color: 'var(--text-light)' }}>
            Drift history ({runs.data.length})
          </summary>
          <table className="data-table" style={{ width: '100%', marginTop: 8 }}>
            <thead>
              <tr>
                <th>When</th>
                <th>Status</th>
                <th>+/−</th>
                <th>By</th>
              </tr>
            </thead>
            <tbody>
              {runs.data.map((r) => (
                <tr key={r.id}>
                  <td>{r.checked_at}</td>
                  <td>{driftBadge(r.status)}</td>
                  <td>+{r.diff_added}/−{r.diff_removed}</td>
                  <td>{r.actor || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}
    </div>
  );
}
