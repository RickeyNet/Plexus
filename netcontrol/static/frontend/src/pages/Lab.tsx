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
  useCreateDevice,
  useCreateEnvironment,
  useDeleteDevice,
  useDeleteEnvironment,
  useEnvironment,
  useEnvironments,
  useRun,
  useRuns,
  useSimulate,
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
                        <td style={{ padding: 6 }}>{d.ip_address || '—'}</td>
                        <td style={{ padding: 6 }}>{d.device_type}</td>
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
  const runs = useRuns(deviceId);
  const [commandsText, setCommandsText] = useState('');
  const [applyToDevice, setApplyToDevice] = useState(false);
  const simulate = useSimulate(deviceId);
  const [openRunId, setOpenRunId] = useState<number | null>(null);

  const lastResult = simulate.data;

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
              <FormGroup fieldId="sim-apply">
                <Checkbox
                  id="sim-apply"
                  label="Persist resulting config back to lab device snapshot"
                  isChecked={applyToDevice}
                  onChange={(_, v) => setApplyToDevice(v)}
                />
              </FormGroup>
              <Button
                variant="primary"
                isDisabled={commandList.length === 0 || simulate.isPending}
                onClick={() =>
                  simulate.mutate({
                    proposed_commands: commandList,
                    apply_to_device: applyToDevice,
                  })
                }
              >
                Run simulation
              </Button>
              {simulate.error && (
                <Alert variant="danger" title="Simulation failed" isInline>
                  {(simulate.error as Error).message}
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
              </Content>
              <pre style={PRE_STYLE}>{lastResult.diff_text || '(no diff)'}</pre>
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
