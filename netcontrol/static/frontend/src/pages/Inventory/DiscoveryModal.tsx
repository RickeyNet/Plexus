import { FormEvent, useEffect, useId, useRef, useState } from 'react';

import { useAuthStatus } from '@/api/auth';
import { Callout } from '@/components/Callout';
import { CredentialSelect } from '@/components/CredentialSelect';
import { useDialogs } from '@/components/DialogProvider-context';
import { Modal } from '@/components/Modal';
import {
  type DiscoveredHost,
  type DiscoveryOptions,
  type InventoryGroupFull,
  type ScanStreamEvent,
  type SshEnrichmentSummary,
  streamScanInventoryGroup,
  streamSyncInventoryGroup,
  useDiscoverySshDefaults,
  useOnboardDiscoveredHosts,
  useTestGroupSnmpProfile,
  groupLabel,
} from '@/api/inventory';
import { credentialIdFromChoice } from '@/lib/credentialChoice';
import { useCredentialChoice } from '@/lib/useCredentialChoice';

import {
  describeSshEnrichment,
  discoveredHostFacts,
  discoveredHostSshError,
} from './helpers';

export type DiscoveryMode = 'sync' | 'scan' | 'global';

interface Props {
  mode: DiscoveryMode;
  group: InventoryGroupFull | null;
  groups: InventoryGroupFull[];
  onClose: () => void;
}

type Phase =
  | 'form'
  | 'scanning'
  | 'results'
  | 'snmp-result'
  | 'sync-result'
  | 'onboard-result';

interface SyncResult {
  added: number;
  updated: number;
  removed: number;
}

interface ScanState {
  total: number | null;
  scanned: number;
  found: number;
  currentIp: string;
  feed: { ip: string; hostname?: string; deviceType?: string; facts?: string; sshError?: string }[];
  startedAt: number;
  // Sync only: probing finished, now reconciling with the database.
  syncing: boolean;
}

export function DiscoveryModal({ mode, group, groups, onClose }: Props) {
  const isSync = mode === 'sync';
  const isGlobal = mode === 'global';
  const { confirm } = useDialogs();
  const onboard = useOnboardDiscoveredHosts();
  const testSnmp = useTestGroupSnmpProfile();
  const isAdmin = useAuthStatus().data?.role === 'admin';
  const sshDefaults = useDiscoverySshDefaults();
  const serviceCredentialId = sshDefaults.data?.service_credential_id ?? null;
  const credentialChoice = useCredentialChoice(serviceCredentialId, isAdmin);

  const initialCidrs = isSync && group?.hosts
    ? (group.hosts.map((h) => h.ip_address).filter(Boolean) as string[]).join('\n')
    : '';

  const [phase, setPhase] = useState<Phase>('form');
  const [groupId, setGroupId] = useState<number>(group?.id ?? groups[0]?.id ?? 0);
  const [cidrs, setCidrs] = useState(initialCidrs);
  const [timeoutSeconds, setTimeoutSeconds] = useState(0.35);
  const [maxHosts, setMaxHosts] = useState(256);
  const [deviceType, setDeviceType] = useState('unknown');
  const [hostnamePrefix, setHostnamePrefix] = useState('discovered');
  const [useSnmp, setUseSnmp] = useState(true);
  const [useIcmp, setUseIcmp] = useState(true);
  const [useSsh, setUseSsh] = useState(true);
  const [sshSummary, setSshSummary] = useState<SshEnrichmentSummary | null>(null);
  const [removeAbsent, setRemoveAbsent] = useState(false);
  const [testOnly, setTestOnly] = useState(false);
  const [testTargetIp, setTestTargetIp] = useState('');

  const [scanState, setScanState] = useState<ScanState | null>(null);
  const [discovered, setDiscovered] = useState<DiscoveredHost[]>([]);
  const [selectedSet, setSelectedSet] = useState<Set<number>>(new Set());
  const [snmpResult, setSnmpResult] = useState<
    | null
    | { ok: true; data: NonNullable<ReturnType<typeof useTestGroupSnmpProfile>['data']>['result'] }
    | { ok: false; error: string }
  >(null);
  const [syncResult, setSyncResult] = useState<SyncResult | null>(null);
  const [onboardResult, setOnboardResult] = useState<{
    added: number;
    updated: number;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tickNow, setTickNow] = useState(() => Date.now());
  const formId = useId();

  const scanAbortRef = useRef<AbortController | null>(null);

  useEffect(
    () => () => {
      scanAbortRef.current?.abort();
    },
    [],
  );

  // Tick the elapsed timer while scanning.
  useEffect(() => {
    if (phase !== 'scanning') return;
    const id = window.setInterval(() => setTickNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, [phase]);

  const buildOpts = (): DiscoveryOptions => ({
    timeoutSeconds,
    maxHosts,
    deviceType: deviceType.trim() || 'unknown',
    hostnamePrefix: hostnamePrefix.trim() || 'discovered',
    useSnmp,
    useIcmp,
    useSsh,
    credentialId: credentialIdFromChoice(credentialChoice.credential),
    removeAbsent,
  });

  const feedEntry = (host: DiscoveredHost): ScanState['feed'][number] => ({
    ip: host.ip_address,
    hostname: host.hostname,
    deviceType: host.device_type,
    facts: discoveredHostFacts(host),
    sshError: discoveredHostSshError(host),
  });

  const parsedCidrs = cidrs
    .split(/[\n,]+/)
    .map((v) => v.trim())
    .filter(Boolean);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSshSummary(null);

    if (isGlobal && testOnly) {
      const targetIp = testTargetIp.trim();
      if (!targetIp) {
        setError('Target IP is required for SNMP test.');
        return;
      }
      try {
        const r = await testSnmp.mutateAsync({ groupId, targetIp });
        if (r.success) {
          setSnmpResult({ ok: true, data: r.result });
        } else {
          setSnmpResult({ ok: false, error: r.error || 'Unknown error' });
        }
        setPhase('snmp-result');
      } catch (err) {
        setError(`SNMP test failed: ${(err as Error).message}`);
      }
      return;
    }

    if (parsedCidrs.length === 0 && !isSync) {
      setError('At least one CIDR target is required.');
      return;
    }

    if (isSync && removeAbsent) {
      const hostCount = group?.hosts?.length ?? 0;
      const groupName = group ? groupLabel(group) : 'this group';
      if (
        !(await confirm({
          title: 'Run sync and remove hosts',
          message:
            `Hosts in "${groupName}" that this scan does not find will be deleted from inventory. ` +
            `The group has ${hostCount} host${hostCount === 1 ? '' : 's'}; any of them that do not answer are removed. ` +
            'This cannot be undone.',
          confirmLabel: 'Run Sync',
        }))
      )
        return;
    }

    // Scan and sync both stream live per-host progress; sync ends with a
    // reconcile phase and a result card, scan ends with a results picker.
    setPhase('scanning');
    setScanState({
      total: null,
      scanned: 0,
      found: 0,
      currentIp: '',
      feed: [],
      startedAt: Date.now(),
      syncing: false,
    });

    const abort = new AbortController();
    scanAbortRef.current = abort;

    if (isSync) {
      try {
        const targetGroupId = group?.id ?? groupId;
        let finalSync: SyncResult | null = null;
        await streamSyncInventoryGroup(
          targetGroupId,
          parsedCidrs,
          buildOpts(),
          (event: ScanStreamEvent) => {
            if (event.type === 'start') {
              setScanState((prev) =>
                prev ? { ...prev, total: event.total ?? prev.total } : prev,
              );
            } else if (event.type === 'progress') {
              setScanState((prev) => {
                if (!prev) return prev;
                const next = {
                  ...prev,
                  scanned: event.scanned ?? prev.scanned,
                  currentIp: event.ip ?? prev.currentIp,
                };
                if (event.found && event.host) {
                  next.found = prev.found + 1;
                  next.feed = [...prev.feed, feedEntry(event.host)];
                }
                return next;
              });
            } else if (event.type === 'syncing') {
              setScanState((prev) => (prev ? { ...prev, syncing: true } : prev));
            } else if (event.type === 'done') {
              setSshSummary(event.ssh_enrichment ?? null);
              const s = event.sync || {};
              finalSync = {
                added: s.added || 0,
                updated: s.updated || 0,
                removed: s.removed || 0,
              };
            }
          },
          abort.signal,
        );

        setSyncResult(finalSync ?? { added: 0, updated: 0, removed: 0 });
        setPhase('sync-result');
      } catch (err) {
        if ((err as Error).name === 'AbortError') return;
        setError(`Sync failed: ${(err as Error).message}`);
        setPhase('form');
      } finally {
        scanAbortRef.current = null;
      }
      return;
    }

    try {
      let finalDiscovered: DiscoveredHost[] = [];
      const targetGroupId = isGlobal ? groupId : group?.id ?? groupId;
      await streamScanInventoryGroup(
        targetGroupId,
        parsedCidrs,
        buildOpts(),
        (event: ScanStreamEvent) => {
          if (event.type === 'start') {
            setScanState((prev) =>
              prev ? { ...prev, total: event.total ?? prev.total } : prev,
            );
          } else if (event.type === 'progress') {
            setScanState((prev) => {
              if (!prev) return prev;
              const next = {
                ...prev,
                scanned: event.scanned ?? prev.scanned,
                currentIp: event.ip ?? prev.currentIp,
              };
              if (event.found && event.host) {
                next.found = prev.found + 1;
                next.feed = [...prev.feed, feedEntry(event.host)];
              }
              return next;
            });
          } else if (event.type === 'done') {
            finalDiscovered = event.discovered_hosts || [];
            setSshSummary(event.ssh_enrichment ?? null);
          }
        },
        abort.signal,
      );

      setDiscovered(finalDiscovered);
      setSelectedSet(new Set(finalDiscovered.map((_, i) => i)));
      setPhase('results');
    } catch (err) {
      if ((err as Error).name === 'AbortError') return;
      setError(`Discovery scan failed: ${(err as Error).message}`);
      setPhase('form');
    } finally {
      scanAbortRef.current = null;
    }
  };

  const onboardSelected = async () => {
    if (selectedSet.size === 0) {
      setError('Select at least one host to onboard.');
      return;
    }
    setError(null);
    const selected = Array.from(selectedSet)
      .map((i) => discovered[i])
      .filter(Boolean);
    try {
      const targetGroupId = isGlobal ? groupId : group?.id ?? groupId;
      const r = await onboard.mutateAsync({
        groupId: targetGroupId,
        hosts: selected,
      });
      const s = r.sync || {};
      setOnboardResult({ added: s.added || 0, updated: s.updated || 0 });
      setPhase('onboard-result');
    } catch (err) {
      setError(`Onboarding failed: ${(err as Error).message}`);
    }
  };

  const titlePrefix = isSync
    ? 'Discovery Sync'
    : isGlobal
      ? 'Discover Devices'
      : 'Discovery Scan';
  const title = group ? `${titlePrefix}: ${groupLabel(group)}` : titlePrefix;

  if (phase === 'sync-result' && syncResult) {
    return (
      <Modal
        isOpen
        onClose={onClose}
        title={title}
        footer={
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
        }
      >
        <div
          className="card card-sm"
          style={{ borderLeft: '3px solid var(--success)' }}
        >
          <strong>Sync complete</strong>
          <table className="data-table table-sm" style={{ marginTop: '0.5rem' }}>
            <tbody>
              <tr>
                <td style={{ opacity: 0.7 }}>Added</td>
                <td>{syncResult.added}</td>
              </tr>
              <tr>
                <td style={{ opacity: 0.7 }}>Updated</td>
                <td>{syncResult.updated}</td>
              </tr>
              <tr>
                <td style={{ opacity: 0.7 }}>Removed</td>
                <td>{syncResult.removed}</td>
              </tr>
            </tbody>
          </table>
          <SshSummaryNote summary={sshSummary} />
        </div>
      </Modal>
    );
  }

  if (phase === 'onboard-result' && onboardResult) {
    return (
      <Modal
        isOpen
        onClose={onClose}
        title={title}
        size="small"
        footer={
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
        }
      >
        <div
          className="card card-sm"
          style={{ borderLeft: '3px solid var(--success)' }}
        >
          <strong>Onboard complete</strong>
          <table className="data-table table-sm" style={{ marginTop: '0.5rem' }}>
            <tbody>
              <tr>
                <td style={{ opacity: 0.7 }}>Added</td>
                <td>{onboardResult.added}</td>
              </tr>
              <tr>
                <td style={{ opacity: 0.7 }}>Updated</td>
                <td>{onboardResult.updated}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </Modal>
    );
  }

  if (phase === 'snmp-result' && snmpResult) {
    return (
      <Modal
        isOpen
        onClose={onClose}
        title="SNMP Test Result"
        footer={
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
        }
      >
        {snmpResult.ok ? (
          <div
            className="card card-sm"
            style={{ borderLeft: '3px solid var(--success)' }}
          >
            <strong>SNMP OK</strong> - credentials validated
            <table className="data-table table-sm" style={{ marginTop: '0.5rem' }}>
              <tbody>
                <tr>
                  <td style={{ opacity: 0.7 }}>Hostname</td>
                  <td>{snmpResult.data?.hostname || ''}</td>
                </tr>
                <tr>
                  <td style={{ opacity: 0.7 }}>IP</td>
                  <td>{snmpResult.data?.ip_address || ''}</td>
                </tr>
                <tr>
                  <td style={{ opacity: 0.7 }}>Device Type</td>
                  <td>{snmpResult.data?.device_type || ''}</td>
                </tr>
                <tr>
                  <td style={{ opacity: 0.7 }}>Protocol</td>
                  <td>{snmpResult.data?.discovery?.protocol || ''}</td>
                </tr>
                <tr>
                  <td style={{ opacity: 0.7 }}>Vendor</td>
                  <td>{snmpResult.data?.discovery?.vendor || 'unknown'}</td>
                </tr>
                <tr>
                  <td style={{ opacity: 0.7 }}>OS</td>
                  <td>{snmpResult.data?.discovery?.os || 'unknown'}</td>
                </tr>
                <tr>
                  <td style={{ opacity: 0.7 }}>sysDescr</td>
                  <td style={{ wordBreak: 'break-word' }}>
                    {snmpResult.data?.discovery?.sys_descr || ''}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        ) : (
          <div
            className="card card-sm"
            style={{ borderLeft: '3px solid var(--danger)' }}
          >
            <strong>SNMP Failed</strong>
            <br />
            <span style={{ opacity: 0.8 }}>{snmpResult.error}</span>
          </div>
        )}
      </Modal>
    );
  }

  if (phase === 'scanning' && scanState) {
    const elapsed = Math.floor((tickNow - scanState.startedAt) / 1000);
    const elapsedLabel =
      elapsed < 60 ? `${elapsed}s` : `${Math.floor(elapsed / 60)}m ${elapsed % 60}s`;
    const pct = scanState.syncing
      ? 100
      : scanState.total
        ? (scanState.scanned / scanState.total) * 100
        : 0;
    return (
      <Modal
        isOpen
        onClose={onClose}
        title={isSync ? title : 'Scanning Network'}
        size="medium"
        footer={
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => {
              scanAbortRef.current?.abort();
              onClose();
            }}
          >
            Cancel
          </button>
        }
      >
        <div style={{ padding: '1rem 0.5rem' }}>
          <div style={{ marginBottom: '0.75rem', fontWeight: 600 }}>
            {scanState.syncing
              ? 'Saving inventory changes…'
              : scanState.total
                ? `${isSync ? 'Syncing' : 'Scanning'} ${scanState.total} host(s)…`
                : `Initializing ${isSync ? 'sync' : 'scan'}…`}
          </div>
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              fontSize: '0.8rem',
              color: 'var(--text-muted)',
              marginBottom: '0.35rem',
            }}
          >
            <span>
              {scanState.scanned} / {scanState.total ?? '?'} scanned
            </span>
            <span style={{ color: 'var(--success)', fontWeight: 600 }}>
              {scanState.found} found
            </span>
          </div>
          <div
            style={{
              height: 6,
              background: 'var(--bg-secondary)',
              borderRadius: 3,
              overflow: 'hidden',
              marginBottom: '0.5rem',
            }}
          >
            <div
              style={{
                height: '100%',
                width: `${Math.round(pct)}%`,
                background: 'var(--primary)',
                borderRadius: 3,
                transition: 'width 0.15s ease',
              }}
            />
          </div>
          <div
            style={{
              color: 'var(--text-muted)',
              fontSize: '0.8rem',
              marginBottom: '0.5rem',
            }}
          >
            Elapsed: {elapsedLabel} ·{' '}
            {scanState.syncing
              ? 'Reconciling with inventory…'
              : `Currently scanning: ${scanState.currentIp || '…'}`}
          </div>
          <div
            style={{
              maxHeight: 180,
              overflowY: 'auto',
              border: '1px solid var(--border)',
              borderRadius: '0.5rem',
              padding: '0.4rem 0.6rem',
              fontSize: '0.8rem',
              fontFamily: 'monospace',
              background: 'var(--bg-secondary)',
            }}
          >
            {scanState.feed.map((entry, i) => (
              <div
                key={`${entry.ip}-${i}`}
                style={{
                  padding: '0.2rem 0',
                  borderBottom: '1px solid var(--border)',
                  color: 'var(--success)',
                }}
              >
                ✓ {entry.ip} - {entry.hostname || 'unknown'} (
                {entry.deviceType || 'unknown'})
                {entry.facts ? ` ${entry.facts}` : ''}
                {entry.sshError && (
                  <span style={{ color: 'var(--warning)' }}>
                    {' '}
                    SSH: {entry.sshError}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      </Modal>
    );
  }

  if (phase === 'results') {
    const targetGroup = isGlobal
      ? groups.find((g) => g.id === groupId)
      : group;
    const allSelected =
      discovered.length > 0 && selectedSet.size === discovered.length;
    return (
      <Modal
        isOpen
        onClose={onClose}
        title="Discovered Devices"
        size="medium"
        footer={
          <>
            <button
              type="button"
              className="btn btn-secondary modal-footer-start"
              onClick={() =>
                setSelectedSet(
                  allSelected
                    ? new Set()
                    : new Set(discovered.map((_, i) => i)),
                )
              }
            >
              {allSelected ? 'Deselect All' : 'Select All'}
            </button>
            <button type="button" className="btn btn-secondary" onClick={onClose}>
              Close
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={onboard.isPending || discovered.length === 0}
              onClick={onboardSelected}
            >
              {onboard.isPending ? 'Onboarding…' : 'Onboard Selected'}
            </button>
          </>
        }
      >
        {error && <Callout tone="danger">{error}</Callout>}
        <div className="card-description" style={{ marginBottom: '0.75rem' }}>
          Found {discovered.length} reachable device(s). Will onboard into{' '}
          <strong>{targetGroup?.name ?? 'selected group'}</strong>.
          <SshSummaryNote summary={sshSummary} />
        </div>
        <div
          style={{
            maxHeight: 340,
            overflow: 'auto',
            border: '1px solid var(--border)',
            borderRadius: '0.5rem',
            padding: '0.5rem',
          }}
        >
          {discovered.length ? (
            discovered.map((host, idx) => (
              <label
                key={`${host.ip_address}-${idx}`}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  marginBottom: '0.4rem',
                  padding: '0.25rem 0',
                  borderBottom: '1px solid var(--border)',
                }}
              >
                <input
                  type="checkbox"
                  checked={selectedSet.has(idx)}
                  onChange={(e) => {
                    setSelectedSet((prev) => {
                      const next = new Set(prev);
                      if (e.target.checked) next.add(idx);
                      else next.delete(idx);
                      return next;
                    });
                  }}
                />
                <span style={{ flex: 1, minWidth: 0 }}>
                  {host.hostname || '-'}
                  {discoveredHostFacts(host) && (
                    <span
                      style={{
                        display: 'block',
                        fontSize: '0.8em',
                        color: 'var(--text-muted)',
                      }}
                    >
                      {discoveredHostFacts(host)}
                    </span>
                  )}
                  {discoveredHostSshError(host) && (
                    <span
                      style={{
                        display: 'block',
                        fontSize: '0.8em',
                        color: 'var(--warning)',
                      }}
                    >
                      SSH: {discoveredHostSshError(host)}
                    </span>
                  )}
                </span>
                <span style={{ color: 'var(--text-muted)' }}>
                  {host.ip_address}
                </span>
                <span
                  style={{ color: 'var(--text-muted)', fontSize: '0.85em' }}
                  title={
                    host.discovery?.device_type_source === 'ssh'
                      ? 'Reported by show version over SSH'
                      : 'Guessed from the SNMP description or SSH banner'
                  }
                >
                  {host.device_type || 'unknown'}
                  {host.discovery?.device_type_source === 'ssh' ? ' (SSH)' : ''}
                </span>
              </label>
            ))
          ) : (
            <div className="empty-state" style={{ padding: '1rem' }}>
              No reachable hosts discovered.
            </div>
          )}
        </div>
      </Modal>
    );
  }

  // Form phase
  return (
    <Modal
      isOpen
      onClose={onClose}
      title={title}
      size="medium"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button
            type="submit"
            form={formId}
            className="btn btn-primary"
            disabled={testSnmp.isPending}
          >
            {isSync
              ? 'Run Sync'
              : testOnly
                ? testSnmp.isPending
                  ? 'Testing…'
                  : 'Test SNMP'
                : 'Scan Network'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={submit}>
        {error && <Callout tone="danger">{error}</Callout>}
        {isGlobal && (
          <div className="form-group">
            <label className="form-label">Target Inventory Group</label>
            <select
              className="form-select"
              value={String(groupId)}
              onChange={(e) => setGroupId(Number(e.target.value))}
              required
            >
              {groups.map((g) => (
                <option key={g.id} value={g.id}>
                  {groupLabel(g)}
                </option>
              ))}
            </select>
            <div className="form-help">
              Discovered devices will be onboarded into this group.
            </div>
          </div>
        )}
        <div className="form-group">
          <label className="form-label">CIDR Targets</label>
          <textarea
            className="form-textarea"
            value={cidrs}
            onChange={(e) => setCidrs(e.target.value)}
            placeholder={'10.0.0.0/24\n10.0.1.0/24'}
            required={!isSync && !testOnly}
          />
          <div className="form-help">
            {isSync
              ? 'Pre-filled with group host IPs. Leave as-is to sync existing hosts, or edit to scan different targets.'
              : 'One CIDR per line or comma-separated.'}
          </div>
        </div>
        <div
          className="form-group"
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: '0.75rem',
          }}
        >
          <div>
            <label className="form-label">Timeout Seconds</label>
            <input
              className="form-input"
              type="number"
              min={0.05}
              max={5}
              step={0.05}
              value={timeoutSeconds}
              onChange={(e) => setTimeoutSeconds(Number(e.target.value || 0.35))}
            />
          </div>
          <div>
            <label className="form-label">Max Hosts</label>
            <input
              className="form-input"
              type="number"
              min={1}
              max={4096}
              value={maxHosts}
              onChange={(e) => setMaxHosts(Number(e.target.value || 256))}
            />
          </div>
        </div>
        <div
          className="form-group"
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: '0.75rem',
          }}
        >
          <div>
            <label className="form-label">Device Type</label>
            <input
              className="form-input"
              value={deviceType}
              onChange={(e) => setDeviceType(e.target.value)}
            />
          </div>
          <div>
            <label className="form-label">Hostname Prefix</label>
            <input
              className="form-input"
              value={hostnamePrefix}
              onChange={(e) => setHostnamePrefix(e.target.value)}
            />
          </div>
        </div>
        <label
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
            marginTop: '0.5rem',
          }}
        >
          <input
            type="checkbox"
            checked={useSnmp}
            onChange={(e) => setUseSnmp(e.target.checked)}
          />{' '}
          Use SNMP discovery first (falls back to TCP probe)
        </label>
        <label
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
            marginTop: '0.5rem',
          }}
        >
          <input
            type="checkbox"
            checked={useIcmp}
            onChange={(e) => setUseIcmp(e.target.checked)}
          />{' '}
          Fall back to ICMP ping (catches firewalls / appliances with locked-down management)
        </label>
        {!testOnly && (
          <>
            <label
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
                marginTop: '0.5rem',
              }}
            >
              <input
                type="checkbox"
                checked={useSsh}
                onChange={(e) => setUseSsh(e.target.checked)}
              />{' '}
              Read model/serial/version over SSH (show version also sets the
              device type, no SNMP needed)
            </label>
            {useSsh && (
              <div className="form-group" style={{ marginTop: '0.5rem' }}>
                <label className="form-label" htmlFor="discovery-ssh-credential">
                  SSH Credential
                </label>
                <CredentialSelect
                  id="discovery-ssh-credential"
                  choice={credentialChoice}
                  serviceCredentialId={serviceCredentialId}
                  isAdmin={isAdmin}
                />
                <div className="form-help">
                  {sshDefaults.data && !sshDefaults.data.service_credential
                    ? 'No Plexus service credential is set in Settings: pick a credential, or hosts are found without SSH details.'
                    : 'Defaults to the Plexus service credential. Hosts that refuse the login are still found; the error is shown per host.'}
                </div>
              </div>
            )}
          </>
        )}
        {isSync && (
          <label
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
              marginTop: '0.5rem',
            }}
          >
            <input
              type="checkbox"
              checked={removeAbsent}
              onChange={(e) => setRemoveAbsent(e.target.checked)}
            />{' '}
            Remove hosts not found in this scan
          </label>
        )}
        {isGlobal && (
          <>
            <label
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
                marginTop: '0.5rem',
              }}
            >
              <input
                type="checkbox"
                checked={testOnly}
                onChange={(e) => setTestOnly(e.target.checked)}
              />{' '}
              Test only (validate SNMP credentials against a single IP without
              scanning)
            </label>
            {testOnly && (
              <div className="form-group" style={{ marginTop: '0.5rem' }}>
                <label className="form-label">Test Target IP</label>
                <input
                  className="form-input"
                  value={testTargetIp}
                  onChange={(e) => setTestTargetIp(e.target.value)}
                  placeholder="e.g. 10.0.0.1"
                  pattern="^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
                  title="Enter a valid IPv4 address"
                  required
                />
                <div className="form-help">
                  Single IP to test SNMP credentials against.
                </div>
              </div>
            )}
          </>
        )}
      </form>
    </Modal>
  );
}

/** The SSH show version summary under a scan or sync result, with each host that failed. */
function SshSummaryNote({ summary }: { summary: SshEnrichmentSummary | null }) {
  if (!summary) return null;
  const failures = summary.failures ?? [];
  return (
    <div style={{ marginTop: '0.5rem', fontSize: '0.85rem' }}>
      <div style={{ opacity: 0.8 }}>{describeSshEnrichment(summary)}</div>
      {failures.length > 0 && (
        <ul style={{ margin: '0.25rem 0 0', paddingLeft: '1.1rem', color: 'var(--warning)' }}>
          {failures.slice(0, 20).map((f) => (
            <li key={f.ip_address}>
              {f.ip_address}: {f.error}
            </li>
          ))}
          {failures.length > 20 && <li>and {failures.length - 20} more</li>}
        </ul>
      )}
    </div>
  );
}
