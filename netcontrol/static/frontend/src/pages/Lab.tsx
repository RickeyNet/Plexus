import { useMemo, useState } from 'react';
import {
  Alert,
  Bullseye,
  Button,
  Card,
  CardBody,
  CardTitle,
  Checkbox,
  Content,
  EmptyState,
  EmptyStateBody,
  Form,
  FormGroup,
  Label,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  ModalVariant,
  Spinner,
  Split,
  SplitItem,
  Stack,
  StackItem,
  TextArea,
  TextInput,
  Title,
} from '@patternfly/react-core';

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
  useEnvironment,
  useEnvironments,
  useRefreshRuntime,
  useRefreshTopology,
  useRemoveTopologyLink,
  useRemoveTopologyMember,
  useRun,
  useRuns,
  useRuntimeEvents,
  useRuntimeStatus,
  useSimulate,
  useSimulateLive,
  useTopologies,
  useTopology,
} from '@/api/lab';

const PRE_STYLE: React.CSSProperties = {
  background: 'var(--pf-v6-global--BackgroundColor--200, #f5f5f5)',
  padding: 12,
  maxHeight: 400,
  overflow: 'auto',
  fontSize: '0.8em',
  fontFamily: 'JetBrains Mono, ui-monospace, monospace',
  whiteSpace: 'pre',
};

function riskBadge(level: string) {
  const color: 'red' | 'orange' | 'yellow' | 'green' | 'grey' =
    level === 'critical' ? 'red' :
    level === 'high' ? 'orange' :
    level === 'medium' ? 'yellow' :
    level === 'low' ? 'green' : 'grey';
  return <Label color={color}>{level || 'unknown'}</Label>;
}

function runtimeBadge(status: string | undefined, kind?: string) {
  if (!kind || kind === 'config_only') {
    return <Label color="grey">offline</Label>;
  }
  switch (status) {
    case 'running':
      return <Label color="green">running</Label>;
    case 'provisioning':
      return <Label color="blue">provisioning</Label>;
    case 'stopped':
      return <Label color="grey">stopped</Label>;
    case 'destroyed':
      return <Label color="grey">destroyed</Label>;
    case 'error':
      return <Label color="red">error</Label>;
    default:
      return <Label color="grey">{status || '—'}</Label>;
  }
}

export function Lab() {
  const envs = useEnvironments();
  const [selectedEnvId, setSelectedEnvId] = useState<number | null>(null);
  const [selectedDeviceId, setSelectedDeviceId] = useState<number | null>(null);
  const [createEnvOpen, setCreateEnvOpen] = useState(false);

  const activeEnv = useEnvironment(selectedEnvId);

  return (
    <Stack hasGutter>
      <StackItem>
        <Split hasGutter>
          <SplitItem isFilled>
            <Title headingLevel="h1" size="2xl">
              Lab / Digital Twin
            </Title>
            <Content component="p">
              Safe sandbox for pre-production change testing. Clone a production
              device, apply proposed commands or templates against the simulated
              snapshot, review the diff and risk score, then promote a successful
              change to a real deployment.
            </Content>
          </SplitItem>
          <SplitItem>
            <Button variant="primary" onClick={() => setCreateEnvOpen(true)}>
              New environment
            </Button>
          </SplitItem>
        </Split>
      </StackItem>

      <StackItem>
        <Split hasGutter>
          <SplitItem style={{ minWidth: 280 }}>
            <Card>
              <CardTitle>Environments</CardTitle>
              <CardBody>
                {envs.isPending && (
                  <Bullseye>
                    <Spinner size="md" aria-label="Loading environments" />
                  </Bullseye>
                )}
                {envs.error && (
                  <Alert variant="danger" title="Failed to load" isInline>
                    {(envs.error as Error).message}
                  </Alert>
                )}
                {envs.data && envs.data.length === 0 && (
                  <EmptyState titleText="No environments yet" headingLevel="h4">
                    <EmptyStateBody>
                      Create one to start testing config changes against simulated devices.
                    </EmptyStateBody>
                  </EmptyState>
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
                        selectedEnvId === e.id
                          ? 'var(--pf-v6-global--BackgroundColor--200, #eee)'
                          : 'transparent',
                    }}
                  >
                    <strong>{e.name}</strong>
                    <div style={{ fontSize: '0.85em', opacity: 0.7 }}>
                      {e.device_count ?? 0} device(s){e.shared ? ' · shared' : ''}
                    </div>
                  </button>
                ))}
              </CardBody>
            </Card>
          </SplitItem>

          <SplitItem isFilled>
            {selectedEnvId === null ? (
              <Card>
                <CardBody>
                  <EmptyState titleText="Select an environment" headingLevel="h4">
                    <EmptyStateBody>Pick a lab environment on the left.</EmptyStateBody>
                  </EmptyState>
                </CardBody>
              </Card>
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
          </SplitItem>
        </Split>
      </StackItem>

      {createEnvOpen && (
        <CreateEnvironmentModal onClose={() => setCreateEnvOpen(false)} />
      )}
    </Stack>
  );
}

function CreateEnvironmentModal({ onClose }: { onClose: () => void }) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [shared, setShared] = useState(false);
  const create = useCreateEnvironment();

  return (
    <Modal isOpen variant={ModalVariant.small} onClose={onClose}>
      <ModalHeader title="Create lab environment" />
      <ModalBody>
        <Form>
          <FormGroup label="Name" isRequired fieldId="env-name">
            <TextInput id="env-name" value={name} onChange={(_, v) => setName(v)} />
          </FormGroup>
          <FormGroup label="Description" fieldId="env-description">
            <TextArea
              id="env-description"
              value={description}
              onChange={(_, v) => setDescription(v)}
              rows={3}
            />
          </FormGroup>
          <FormGroup fieldId="env-shared">
            <Checkbox
              id="env-shared"
              label="Shared (visible to all operators)"
              isChecked={shared}
              onChange={(_, v) => setShared(v)}
            />
          </FormGroup>
          {create.error && (
            <Alert variant="danger" title="Failed" isInline>
              {(create.error as Error).message}
            </Alert>
          )}
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button
          variant="primary"
          isDisabled={!name.trim() || create.isPending}
          onClick={async () => {
            await create.mutateAsync({ name: name.trim(), description, shared });
            onClose();
          }}
        >
          Create
        </Button>
        <Button variant="link" onClick={onClose}>
          Cancel
        </Button>
      </ModalFooter>
    </Modal>
  );
}

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

  if (envQuery.isPending) {
    return (
      <Bullseye>
        <Spinner size="lg" aria-label="Loading environment" />
      </Bullseye>
    );
  }
  if (envQuery.error) {
    return (
      <Alert variant="danger" title="Failed to load environment" isInline>
        {(envQuery.error as Error).message}
      </Alert>
    );
  }
  if (!envQuery.data) return null;

  const env = envQuery.data;
  const devices: LabDeviceSummary[] = env.devices ?? [];

  return (
    <Stack hasGutter>
      <StackItem>
        <Card>
          <CardTitle>{env.name}</CardTitle>
          <CardBody>
            <Content component="p">
              {env.description || <em>No description.</em>}
            </Content>
            <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
              <Button variant="primary" onClick={() => setCreateDeviceOpen(true)}>
                Add lab device
              </Button>
              <Button
                variant="danger"
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
              </Button>
            </div>
          </CardBody>
        </Card>
      </StackItem>

      <StackItem>
        <Card>
          <CardTitle>Devices ({devices.length})</CardTitle>
          <CardBody>
            {devices.length === 0 ? (
              <EmptyState
                titleText="No devices in this environment"
                headingLevel="h4"
              >
                <EmptyStateBody>
                  Add a blank device or clone one from inventory to start
                  simulating changes.
                </EmptyStateBody>
              </EmptyState>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ textAlign: 'left', borderBottom: '1px solid #ccc' }}>
                    <th style={{ padding: 6 }}>Hostname</th>
                    <th style={{ padding: 6 }}>IP</th>
                    <th style={{ padding: 6 }}>Type</th>
                    <th style={{ padding: 6 }}>Runtime</th>
                    <th style={{ padding: 6 }}>Config</th>
                    <th style={{ padding: 6 }}>Runs</th>
                    <th style={{ padding: 6 }}>Source</th>
                    <th style={{ padding: 6 }} />
                  </tr>
                </thead>
                <tbody>
                  {devices.map((d) => {
                    const selected = selectedDeviceId === d.id;
                    return (
                      <tr
                        key={d.id}
                        style={{
                          borderBottom: '1px solid #eee',
                          background: selected
                            ? 'var(--pf-v6-global--BackgroundColor--200, #f0f0f0)'
                            : undefined,
                          cursor: 'pointer',
                        }}
                        onClick={() => onSelectDevice(d.id)}
                      >
                        <td style={{ padding: 6 }}>{d.hostname}</td>
                        <td style={{ padding: 6 }}>
                          {d.runtime_mgmt_address || d.ip_address || '—'}
                        </td>
                        <td style={{ padding: 6 }}>{d.device_type}</td>
                        <td style={{ padding: 6 }}>
                          {runtimeBadge(d.runtime_status, d.runtime_kind)}
                        </td>
                        <td style={{ padding: 6 }}>{d.config_size} B</td>
                        <td style={{ padding: 6 }}>{d.run_count}</td>
                        <td style={{ padding: 6 }}>
                          {d.source_host_id ? `#${d.source_host_id}` : '—'}
                        </td>
                        <td style={{ padding: 6 }} onClick={(e) => e.stopPropagation()}>
                          <Button
                            variant="link"
                            isDanger
                            onClick={async () => {
                              if (!confirm(`Delete device "${d.hostname}"?`)) return;
                              if (selectedDeviceId === d.id) onSelectDevice(null);
                              await deleteDevice.mutateAsync(d.id);
                            }}
                          >
                            Delete
                          </Button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </CardBody>
        </Card>
      </StackItem>

      {selectedDeviceId !== null && (
        <StackItem>
          <DevicePanel deviceId={selectedDeviceId} />
        </StackItem>
      )}

      <StackItem>
        <TopologiesCard envId={envId} devices={devices} />
      </StackItem>

      {createDeviceOpen && (
        <CreateDeviceModal envId={envId} onClose={() => setCreateDeviceOpen(false)} />
      )}
    </Stack>
  );
}

function CreateDeviceModal({ envId, onClose }: { envId: number; onClose: () => void }) {
  const [hostname, setHostname] = useState('');
  const [ip, setIp] = useState('');
  const [deviceType, setDeviceType] = useState('cisco_ios');
  const [config, setConfig] = useState('');
  const [cloneHostId, setCloneHostId] = useState('');
  const create = useCreateDevice(envId);

  return (
    <Modal isOpen variant={ModalVariant.medium} onClose={onClose}>
      <ModalHeader title="Add lab device" />
      <ModalBody>
        <Form>
          <FormGroup label="Hostname" isRequired fieldId="dev-name">
            <TextInput id="dev-name" value={hostname} onChange={(_, v) => setHostname(v)} />
          </FormGroup>
          <FormGroup label="IP address" fieldId="dev-ip">
            <TextInput id="dev-ip" value={ip} onChange={(_, v) => setIp(v)} />
          </FormGroup>
          <FormGroup label="Device type" fieldId="dev-type">
            <TextInput id="dev-type" value={deviceType} onChange={(_, v) => setDeviceType(v)} />
          </FormGroup>
          <FormGroup label="Initial running config (optional)" fieldId="dev-config">
            <TextArea
              id="dev-config"
              value={config}
              onChange={(_, v) => setConfig(v)}
              rows={6}
              placeholder="Paste a known-good config or leave empty."
            />
          </FormGroup>
          <FormGroup label="Or clone from inventory host ID" fieldId="dev-clone">
            <TextInput
              id="dev-clone"
              value={cloneHostId}
              onChange={(_, v) => setCloneHostId(v)}
              placeholder="e.g. 42"
            />
          </FormGroup>
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button
          variant="primary"
          isDisabled={!hostname.trim() || create.isPending}
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
        </Button>
        <Button
          variant="secondary"
          isDisabled={!cloneHostId || Number.isNaN(Number(cloneHostId))}
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
        </Button>
        <Button variant="link" onClick={onClose}>
          Cancel
        </Button>
      </ModalFooter>
    </Modal>
  );
}

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
    <Stack hasGutter>
      <StackItem>
        <RuntimeCard deviceId={deviceId} />
      </StackItem>

      <StackItem>
        <Card>
          <CardTitle>Simulate change against device #{deviceId}</CardTitle>
          <CardBody>
            <Form>
              <FormGroup label="Proposed commands (one per line)" fieldId="sim-cmds">
                <TextArea
                  id="sim-cmds"
                  value={commandsText}
                  onChange={(_, v) => setCommandsText(v)}
                  rows={6}
                  placeholder={'interface GigabitEthernet0/1\n description uplink\n no shutdown'}
                />
              </FormGroup>
              <FormGroup fieldId="sim-live">
                <Checkbox
                  id="sim-live"
                  label="Live mode (push to running containerlab device)"
                  isChecked={liveMode}
                  isDisabled={!isRuntimeRunning}
                  onChange={(_, v) => setLiveMode(v)}
                />
                {!isRuntimeRunning && (
                  <Content component="small">
                    Deploy a containerlab runtime above to enable live mode.
                  </Content>
                )}
              </FormGroup>
              {!liveMode && (
                <FormGroup fieldId="sim-apply">
                  <Checkbox
                    id="sim-apply"
                    label="Persist resulting config back to lab device snapshot"
                    isChecked={applyToDevice}
                    onChange={(_, v) => setApplyToDevice(v)}
                  />
                </FormGroup>
              )}
              <Button
                variant="primary"
                isDisabled={commandList.length === 0 || isPending}
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
              </Button>
              {lastError && (
                <Alert variant="danger" title="Simulation failed" isInline>
                  {lastError.message}
                </Alert>
              )}
            </Form>
          </CardBody>
        </Card>
      </StackItem>

      {lastResult && (
        <StackItem>
          <Card>
            <CardTitle>
              Last result — {riskBadge(lastResult.risk_level)} (score{' '}
              {lastResult.risk_score})
            </CardTitle>
            <CardBody>
              <Content component="p">
                +{lastResult.diff_added} / −{lastResult.diff_removed} lines
                {lastResult.affected_areas.length > 0 && (
                  <> · areas: {lastResult.affected_areas.join(', ')}</>
                )}
                {liveMode && <> · <strong>live</strong></>}
              </Content>
              <pre style={PRE_STYLE}>{lastResult.diff_text || '(no diff)'}</pre>
              {liveMode && 'push_output' in lastResult && lastResult.push_output && (
                <>
                  <Title headingLevel="h4" size="md">
                    Device push output
                  </Title>
                  <pre style={{ ...PRE_STYLE, maxHeight: 200 }}>
                    {lastResult.push_output}
                  </pre>
                </>
              )}
            </CardBody>
          </Card>
        </StackItem>
      )}

      <StackItem>
        <Card>
          <CardTitle>Run history</CardTitle>
          <CardBody>
            {runs.isPending && <Spinner size="md" aria-label="Loading runs" />}
            {runs.data && runs.data.length === 0 && (
              <EmptyState titleText="No runs yet" headingLevel="h4">
                <EmptyStateBody>
                  Submit commands above to record a simulation run.
                </EmptyStateBody>
              </EmptyState>
            )}
            {runs.data && runs.data.length > 0 && (
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ textAlign: 'left', borderBottom: '1px solid #ccc' }}>
                    <th style={{ padding: 6 }}>ID</th>
                    <th style={{ padding: 6 }}>When</th>
                    <th style={{ padding: 6 }}>By</th>
                    <th style={{ padding: 6 }}>Risk</th>
                    <th style={{ padding: 6 }}>+/−</th>
                    <th style={{ padding: 6 }}>Status</th>
                    <th style={{ padding: 6 }}>Promoted</th>
                  </tr>
                </thead>
                <tbody>
                  {runs.data.map((r) => (
                    <tr
                      key={r.id}
                      onClick={() => setOpenRunId(r.id)}
                      style={{ cursor: 'pointer', borderBottom: '1px solid #eee' }}
                    >
                      <td style={{ padding: 6 }}>{r.id}</td>
                      <td style={{ padding: 6 }}>{r.created_at}</td>
                      <td style={{ padding: 6 }}>{r.submitted_by || '—'}</td>
                      <td style={{ padding: 6 }}>{riskBadge(r.risk_level)}</td>
                      <td style={{ padding: 6 }}>
                        +{r.diff_added}/−{r.diff_removed}
                      </td>
                      <td style={{ padding: 6 }}>{r.status}</td>
                      <td style={{ padding: 6 }}>
                        {r.promoted_deployment_id ? `#${r.promoted_deployment_id}` : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </CardBody>
        </Card>
      </StackItem>

      {openRunId !== null && (
        <RunDetailModal runId={openRunId} onClose={() => setOpenRunId(null)} />
      )}
    </Stack>
  );
}

function RunDetailModal({ runId, onClose }: { runId: number; onClose: () => void }) {
  const run = useRun(runId);
  return (
    <Modal isOpen variant={ModalVariant.large} onClose={onClose}>
      <ModalHeader title={`Lab run #${runId}`} />
      <ModalBody>
        {run.isPending && <Spinner size="md" aria-label="Loading run" />}
        {run.error && (
          <Alert variant="danger" title="Failed" isInline>
            {(run.error as Error).message}
          </Alert>
        )}
        {run.data && (
          <Stack hasGutter>
            <StackItem>
              <Content component="p">
                {riskBadge(run.data.risk_level)} score {run.data.risk_score} · status{' '}
                <strong>{run.data.status}</strong> · +{run.data.diff_added}/−
                {run.data.diff_removed} lines
              </Content>
            </StackItem>
            <StackItem>
              <Title headingLevel="h4" size="md">
                Diff
              </Title>
              <pre style={{ ...PRE_STYLE, maxHeight: 320 }}>
                {run.data.diff_text || '(no diff)'}
              </pre>
            </StackItem>
            <StackItem>
              <Title headingLevel="h4" size="md">
                Commands
              </Title>
              <pre style={{ ...PRE_STYLE, maxHeight: 200 }}>
                {(run.data.commands || []).join('\n') || '(none)'}
              </pre>
            </StackItem>
          </Stack>
        )}
      </ModalBody>
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
    <Card>
      <CardTitle>
        Containerlab runtime · {runtimeBadge(runtimeStatus, runtimeKind)}
      </CardTitle>
      <CardBody>
        {status.isPending && <Spinner size="md" aria-label="Checking runtime" />}
        {status.data && !status.data.available && (
          <Alert
            variant="warning"
            title="containerlab unavailable on the Plexus host"
            isInline
          >
            {status.data.reason || 'See server logs for details.'} Lab devices
            still work in offline (config-only) mode; live deploy is disabled.
          </Alert>
        )}

        {dev && hasRuntime && (
          <Content component="p">
            <strong>Node kind:</strong> {dev.runtime_node_kind || '—'} ·{' '}
            <strong>Image:</strong> {dev.runtime_image || '—'} ·{' '}
            <strong>Mgmt IP:</strong> {dev.runtime_mgmt_address || '—'}{' '}
            {dev.runtime_lab_name && (
              <>
                · <strong>Lab:</strong> {dev.runtime_lab_name}
              </>
            )}
          </Content>
        )}
        {dev?.runtime_error && (
          <Alert variant="danger" title="Runtime error" isInline>
            {dev.runtime_error}
          </Alert>
        )}

        {!isRunning && !isProvisioning && (
          <Form>
            <FormGroup label="Node kind" fieldId="rt-kind">
              <select
                id="rt-kind"
                value={nodeKind}
                onChange={(e) => setNodeKind(e.target.value)}
                style={{ padding: '6px 8px', minWidth: 200 }}
              >
                {allowedKinds.length === 0 && <option value="linux">linux</option>}
                {allowedKinds.map((k) => (
                  <option key={k} value={k}>
                    {k}
                  </option>
                ))}
              </select>
            </FormGroup>
            <FormGroup label="Container image" fieldId="rt-image">
              <TextInput
                id="rt-image"
                value={image}
                onChange={(_, v) => setImage(v)}
                placeholder="e.g. frrouting/frr:latest, ceos:4.30.0F, ghcr.io/nokia/srlinux:latest"
              />
            </FormGroup>
            <FormGroup label="SSH credential ID (for live push)" fieldId="rt-cred">
              <TextInput
                id="rt-cred"
                value={credentialId}
                onChange={(_, v) => setCredentialId(v)}
                placeholder="optional — required only for live simulate"
              />
            </FormGroup>
            <Button
              variant="primary"
              isDisabled={
                !status.data?.available ||
                !image.trim() ||
                deploy.isPending
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
            </Button>
            {deploy.error && (
              <Alert variant="danger" title="Deploy failed" isInline>
                {(deploy.error as Error).message}
              </Alert>
            )}
          </Form>
        )}

        {(isRunning || isProvisioning || hasRuntime) && (
          <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
            <Button
              variant="secondary"
              isDisabled={refresh.isPending}
              onClick={() => refresh.mutate()}
            >
              Refresh status
            </Button>
            <Button
              variant="danger"
              isDisabled={destroy.isPending}
              onClick={async () => {
                if (!confirm('Destroy the containerlab runtime for this device?')) return;
                await destroy.mutateAsync();
              }}
            >
              Destroy runtime
            </Button>
          </div>
        )}

        {events.data && events.data.length > 0 && (
          <details style={{ marginTop: 16 }}>
            <summary>Runtime event log</summary>
            <table style={{ width: '100%', marginTop: 8, borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ textAlign: 'left', borderBottom: '1px solid #ccc' }}>
                  <th style={{ padding: 4 }}>When</th>
                  <th style={{ padding: 4 }}>Action</th>
                  <th style={{ padding: 4 }}>Status</th>
                  <th style={{ padding: 4 }}>By</th>
                  <th style={{ padding: 4 }}>Detail</th>
                </tr>
              </thead>
              <tbody>
                {events.data.map((e) => (
                  <tr key={e.id} style={{ borderBottom: '1px solid #eee' }}>
                    <td style={{ padding: 4 }}>{e.created_at}</td>
                    <td style={{ padding: 4 }}>{e.action}</td>
                    <td style={{ padding: 4 }}>{e.status}</td>
                    <td style={{ padding: 4 }}>{e.actor || '—'}</td>
                    <td style={{ padding: 4 }}>{e.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </details>
        )}
      </CardBody>
    </Card>
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
    <Card>
      <CardTitle>Topologies (multi-device)</CardTitle>
      <CardBody>
        <Form>
          <Split hasGutter>
            <SplitItem isFilled>
              <FormGroup label="New topology name" fieldId="topo-name">
                <TextInput
                  id="topo-name"
                  value={name}
                  onChange={(_, v) => setName(v)}
                  placeholder="e.g. dual-core-test"
                />
              </FormGroup>
            </SplitItem>
            <SplitItem isFilled>
              <FormGroup label="Description" fieldId="topo-desc">
                <TextInput
                  id="topo-desc"
                  value={description}
                  onChange={(_, v) => setDescription(v)}
                />
              </FormGroup>
            </SplitItem>
            <SplitItem>
              <FormGroup label="Mgmt subnet (optional)" fieldId="topo-mgmt">
                <TextInput
                  id="topo-mgmt"
                  value={mgmt}
                  onChange={(_, v) => setMgmt(v)}
                  placeholder="e.g. 172.20.30.0/24"
                />
              </FormGroup>
            </SplitItem>
            <SplitItem>
              <Button
                variant="primary"
                isDisabled={!name.trim() || create.isPending}
                style={{ marginTop: 24 }}
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
              </Button>
            </SplitItem>
          </Split>
        </Form>

        {create.error && (
          <Alert variant="danger" title="Failed" isInline>
            {(create.error as Error).message}
          </Alert>
        )}

        {list.isPending && <Spinner size="md" aria-label="Loading topologies" />}
        {list.data && list.data.length === 0 && (
          <EmptyState titleText="No topologies yet" headingLevel="h4">
            <EmptyStateBody>
              Create one above, then add member devices and links.
            </EmptyStateBody>
          </EmptyState>
        )}
        {list.data && list.data.length > 0 && (
          <table style={{ width: '100%', marginTop: 12, borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ textAlign: 'left', borderBottom: '1px solid #ccc' }}>
                <th style={{ padding: 6 }}>Name</th>
                <th style={{ padding: 6 }}>Devices</th>
                <th style={{ padding: 6 }}>Links</th>
                <th style={{ padding: 6 }}>Status</th>
                <th style={{ padding: 6 }} />
              </tr>
            </thead>
            <tbody>
              {list.data.map((t) => (
                <tr
                  key={t.id}
                  style={{
                    cursor: 'pointer',
                    borderBottom: '1px solid #eee',
                    background:
                      openId === t.id
                        ? 'var(--pf-v6-global--BackgroundColor--200, #f0f0f0)'
                        : undefined,
                  }}
                  onClick={() => setOpenId(openId === t.id ? null : t.id)}
                >
                  <td style={{ padding: 6 }}>{t.name}</td>
                  <td style={{ padding: 6 }}>{t.device_count ?? 0}</td>
                  <td style={{ padding: 6 }}>{t.link_count ?? 0}</td>
                  <td style={{ padding: 6 }}>{runtimeBadge(t.status, 'containerlab')}</td>
                  <td style={{ padding: 6 }} onClick={(e) => e.stopPropagation()}>
                    <Button
                      variant="link"
                      isDanger
                      isDisabled={t.status === 'running'}
                      onClick={async () => {
                        if (!confirm(`Delete topology "${t.name}"?`)) return;
                        if (openId === t.id) setOpenId(null);
                        await remove.mutateAsync(t.id);
                      }}
                    >
                      Delete
                    </Button>
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
      </CardBody>
    </Card>
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

  if (topo.isPending) return <Spinner size="md" aria-label="Loading topology" />;
  if (topo.error)
    return (
      <Alert variant="danger" title="Failed" isInline>
        {(topo.error as Error).message}
      </Alert>
    );
  if (!topo.data) return null;

  const t = topo.data;
  const isRunning = t.status === 'running';
  const memberIds = new Set(t.devices.map((d) => d.id));
  const candidates = envDevices.filter((d) => !memberIds.has(d.id));

  return (
    <Card isPlain>
      <CardTitle>
        Editing: {t.name} · {runtimeBadge(t.status, 'containerlab')}
      </CardTitle>
      <CardBody>
        {t.error && (
          <Alert variant="danger" title="Topology error" isInline>
            {t.error}
          </Alert>
        )}

        <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
          <Button
            variant="primary"
            isDisabled={isRunning || deploy.isPending || t.devices.length === 0}
            onClick={() => deploy.mutate()}
          >
            Deploy topology
          </Button>
          <Button
            variant="secondary"
            isDisabled={refresh.isPending}
            onClick={() => refresh.mutate()}
          >
            Refresh
          </Button>
          <Button
            variant="danger"
            isDisabled={destroy.isPending || t.status === 'destroyed' || t.status === ''}
            onClick={async () => {
              if (!confirm('Destroy topology?')) return;
              await destroy.mutateAsync();
            }}
          >
            Destroy topology
          </Button>
        </div>
        {deploy.error && (
          <Alert variant="danger" title="Deploy failed" isInline>
            {(deploy.error as Error).message}
          </Alert>
        )}

        <Title headingLevel="h4" size="md">
          Members ({t.devices.length})
        </Title>
        <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: 12 }}>
          <thead>
            <tr style={{ textAlign: 'left', borderBottom: '1px solid #ccc' }}>
              <th style={{ padding: 6 }}>Hostname</th>
              <th style={{ padding: 6 }}>Kind</th>
              <th style={{ padding: 6 }}>Image</th>
              <th style={{ padding: 6 }}>Mgmt IP</th>
              <th style={{ padding: 6 }} />
            </tr>
          </thead>
          <tbody>
            {t.devices.map((d) => (
              <tr key={d.id} style={{ borderBottom: '1px solid #eee' }}>
                <td style={{ padding: 6 }}>{d.hostname}</td>
                <td style={{ padding: 6 }}>{d.runtime_node_kind || '—'}</td>
                <td style={{ padding: 6 }}>{d.runtime_image || '—'}</td>
                <td style={{ padding: 6 }}>{d.runtime_mgmt_address || '—'}</td>
                <td style={{ padding: 6 }}>
                  <Button
                    variant="link"
                    isDanger
                    isDisabled={isRunning}
                    onClick={() => removeMember.mutate(d.id)}
                  >
                    Remove
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {!isRunning && (
          <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
            <select
              value={memberPick}
              onChange={(e) => setMemberPick(e.target.value)}
              style={{ padding: '6px 8px', minWidth: 200 }}
            >
              <option value="">— select a device to add —</option>
              {candidates.map((d) => (
                <option key={d.id} value={String(d.id)}>
                  {d.hostname} ({d.runtime_node_kind || 'no kind'})
                </option>
              ))}
            </select>
            <Button
              variant="secondary"
              isDisabled={!memberPick || addMember.isPending}
              onClick={async () => {
                await addMember.mutateAsync({ device_id: Number(memberPick) });
                setMemberPick('');
              }}
            >
              Add member
            </Button>
            {addMember.error && (
              <Alert variant="danger" title="Add failed" isInline>
                {(addMember.error as Error).message}
              </Alert>
            )}
          </div>
        )}

        <Title headingLevel="h4" size="md">
          Links ({t.links.length})
        </Title>
        <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: 12 }}>
          <thead>
            <tr style={{ textAlign: 'left', borderBottom: '1px solid #ccc' }}>
              <th style={{ padding: 6 }}>A device</th>
              <th style={{ padding: 6 }}>A endpoint</th>
              <th style={{ padding: 6 }}>B device</th>
              <th style={{ padding: 6 }}>B endpoint</th>
              <th style={{ padding: 6 }} />
            </tr>
          </thead>
          <tbody>
            {t.links.map((l) => {
              const a = t.devices.find((d) => d.id === l.a_device_id);
              const b = t.devices.find((d) => d.id === l.b_device_id);
              return (
                <tr key={l.id} style={{ borderBottom: '1px solid #eee' }}>
                  <td style={{ padding: 6 }}>{a?.hostname ?? `#${l.a_device_id}`}</td>
                  <td style={{ padding: 6 }}>{l.a_endpoint}</td>
                  <td style={{ padding: 6 }}>{b?.hostname ?? `#${l.b_device_id}`}</td>
                  <td style={{ padding: 6 }}>{l.b_endpoint}</td>
                  <td style={{ padding: 6 }}>
                    <Button
                      variant="link"
                      isDanger
                      isDisabled={isRunning}
                      onClick={() => removeLink.mutate(l.id)}
                    >
                      Remove
                    </Button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>

        {!isRunning && t.devices.length >= 2 && (
          <Form>
            <Split hasGutter>
              <SplitItem>
                <FormGroup label="A device" fieldId="link-a">
                  <select
                    id="link-a"
                    value={linkA}
                    onChange={(e) => setLinkA(e.target.value)}
                    style={{ padding: '6px 8px', minWidth: 160 }}
                  >
                    <option value="">—</option>
                    {t.devices.map((d) => (
                      <option key={d.id} value={String(d.id)}>
                        {d.hostname}
                      </option>
                    ))}
                  </select>
                </FormGroup>
              </SplitItem>
              <SplitItem>
                <FormGroup label="A endpoint" fieldId="link-a-ep">
                  <TextInput
                    id="link-a-ep"
                    value={linkAEp}
                    onChange={(_, v) => setLinkAEp(v)}
                  />
                </FormGroup>
              </SplitItem>
              <SplitItem>
                <FormGroup label="B device" fieldId="link-b">
                  <select
                    id="link-b"
                    value={linkB}
                    onChange={(e) => setLinkB(e.target.value)}
                    style={{ padding: '6px 8px', minWidth: 160 }}
                  >
                    <option value="">—</option>
                    {t.devices.map((d) => (
                      <option key={d.id} value={String(d.id)}>
                        {d.hostname}
                      </option>
                    ))}
                  </select>
                </FormGroup>
              </SplitItem>
              <SplitItem>
                <FormGroup label="B endpoint" fieldId="link-b-ep">
                  <TextInput
                    id="link-b-ep"
                    value={linkBEp}
                    onChange={(_, v) => setLinkBEp(v)}
                  />
                </FormGroup>
              </SplitItem>
              <SplitItem>
                <Button
                  variant="secondary"
                  isDisabled={
                    !linkA ||
                    !linkB ||
                    linkA === linkB ||
                    !linkAEp.trim() ||
                    !linkBEp.trim() ||
                    addLink.isPending
                  }
                  style={{ marginTop: 24 }}
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
                </Button>
              </SplitItem>
            </Split>
            {addLink.error && (
              <Alert variant="danger" title="Add link failed" isInline>
                {(addLink.error as Error).message}
              </Alert>
            )}
          </Form>
        )}
      </CardBody>
    </Card>
  );
}
