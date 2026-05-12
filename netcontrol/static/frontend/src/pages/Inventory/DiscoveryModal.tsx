import { FormEvent, useEffect, useRef, useState } from 'react';

import { Modal } from '@/components/Modal';
import {
  type DiscoveredHost,
  type DiscoveryOptions,
  type InventoryGroupFull,
  type ScanStreamEvent,
  streamScanInventoryGroup,
  useOnboardDiscoveredHosts,
  useSyncInventoryGroup,
  useTestGroupSnmpProfile,
} from '@/api/inventory';

export type DiscoveryMode = 'sync' | 'scan' | 'global';

interface Props {
  mode: DiscoveryMode;
  group: InventoryGroupFull | null;
  groups: InventoryGroupFull[];
  onClose: () => void;
}

type Phase = 'form' | 'scanning' | 'results' | 'snmp-result';

interface ScanState {
  total: number | null;
  scanned: number;
  found: number;
  currentIp: string;
  feed: { ip: string; hostname?: string; deviceType?: string }[];
  startedAt: number;
}

export function DiscoveryModal({ mode, group, groups, onClose }: Props) {
  const isSync = mode === 'sync';
  const isGlobal = mode === 'global';
  const sync = useSyncInventoryGroup();
  const onboard = useOnboardDiscoveredHosts();
  const testSnmp = useTestGroupSnmpProfile();

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
  const [error, setError] = useState<string | null>(null);
  const [tickNow, setTickNow] = useState(Date.now());

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
    removeAbsent,
  });

  const parsedCidrs = cidrs
    .split(/[\n,]+/)
    .map((v) => v.trim())
    .filter(Boolean);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);

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

    if (isSync) {
      try {
        const targetGroupId = group?.id ?? groupId;
        const r = await sync.mutateAsync({
          groupId: targetGroupId,
          cidrs: parsedCidrs,
          opts: buildOpts(),
        });
        const s = r.sync || {};
        onClose();
        alert(
          `Sync complete. Added ${s.added || 0}, updated ${s.updated || 0}, removed ${s.removed || 0}.`,
        );
      } catch (err) {
        setError(`Sync failed: ${(err as Error).message}`);
      }
      return;
    }

    // Per-group scan or global scan: stream live progress.
    setPhase('scanning');
    setScanState({
      total: null,
      scanned: 0,
      found: 0,
      currentIp: '',
      feed: [],
      startedAt: Date.now(),
    });

    const abort = new AbortController();
    scanAbortRef.current = abort;

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
                next.feed = [
                  ...prev.feed,
                  {
                    ip: event.host.ip_address,
                    hostname: event.host.hostname,
                    deviceType: event.host.device_type,
                  },
                ];
              }
              return next;
            });
          } else if (event.type === 'done') {
            finalDiscovered = event.discovered_hosts || [];
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
      alert('Select at least one host to onboard.');
      return;
    }
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
      onClose();
      alert(
        `Onboard complete. Added ${s.added || 0}, updated ${s.updated || 0}.`,
      );
    } catch (err) {
      alert(`Onboarding failed: ${(err as Error).message}`);
    }
  };

  const titlePrefix = isSync
    ? 'Discovery Sync'
    : isGlobal
      ? 'Discover Devices'
      : 'Discovery Scan';
  const title = group ? `${titlePrefix}: ${group.name}` : titlePrefix;

  if (phase === 'snmp-result' && snmpResult) {
    return (
      <Modal isOpen onClose={onClose} title="SNMP Test Result">
        {snmpResult.ok ? (
          <div
            className="card"
            style={{ borderLeft: '3px solid var(--success)', padding: '0.75rem' }}
          >
            <strong>SNMP OK</strong> - credentials validated
            <table style={{ width: '100%', marginTop: '0.5rem', fontSize: '0.85rem' }}>
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
            className="card"
            style={{ borderLeft: '3px solid var(--danger)', padding: '0.75rem' }}
          >
            <strong>SNMP Failed</strong>
            <br />
            <span style={{ opacity: 0.8 }}>{snmpResult.error}</span>
          </div>
        )}
        <div
          style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.75rem' }}
        >
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>
      </Modal>
    );
  }

  if (phase === 'scanning' && scanState) {
    const elapsed = Math.floor((tickNow - scanState.startedAt) / 1000);
    const elapsedLabel =
      elapsed < 60 ? `${elapsed}s` : `${Math.floor(elapsed / 60)}m ${elapsed % 60}s`;
    const pct = scanState.total ? (scanState.scanned / scanState.total) * 100 : 0;
    return (
      <Modal isOpen onClose={onClose} title="Scanning Network" size="large">
        <div style={{ padding: '1rem 0.5rem' }}>
          <div style={{ marginBottom: '0.75rem', fontWeight: 600 }}>
            {scanState.total
              ? `Scanning ${scanState.total} host(s)…`
              : 'Initializing scan…'}
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
            Elapsed: {elapsedLabel} · Currently scanning:{' '}
            {scanState.currentIp || '…'}
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
              </div>
            ))}
          </div>
          <div
            style={{
              display: 'flex',
              justifyContent: 'flex-end',
              marginTop: '0.75rem',
            }}
          >
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
      <Modal isOpen onClose={onClose} title="Discovered Devices" size="large">
        <div className="card-description" style={{ marginBottom: '0.75rem' }}>
          Found {discovered.length} reachable device(s). Will onboard into{' '}
          <strong>{targetGroup?.name ?? 'selected group'}</strong>.
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
                <span style={{ flex: 1 }}>{host.hostname || '-'}</span>
                <span style={{ color: 'var(--text-muted)' }}>
                  {host.ip_address}
                </span>
                <span style={{ color: 'var(--text-muted)', fontSize: '0.85em' }}>
                  {host.device_type || 'unknown'}
                </span>
              </label>
            ))
          ) : (
            <div className="empty-state" style={{ padding: '1rem' }}>
              No reachable hosts discovered.
            </div>
          )}
        </div>
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            marginTop: '0.75rem',
            gap: '0.5rem',
          }}
        >
          <button
            type="button"
            className="btn btn-secondary"
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
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button
              type="button"
              className="btn btn-primary"
              disabled={onboard.isPending || discovered.length === 0}
              onClick={onboardSelected}
            >
              {onboard.isPending ? 'Onboarding…' : 'Onboard Selected'}
            </button>
            <button type="button" className="btn btn-secondary" onClick={onClose}>
              Close
            </button>
          </div>
        </div>
      </Modal>
    );
  }

  // Form phase
  return (
    <Modal isOpen onClose={onClose} title={title} size="large">
      <form onSubmit={submit}>
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
                  {g.name}
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
        {error && (
          <p
            style={{
              color: 'var(--danger)',
              marginTop: '0.5rem',
              fontSize: '0.85rem',
            }}
          >
            {error}
          </p>
        )}
        <div
          style={{
            display: 'flex',
            gap: '0.5rem',
            justifyContent: 'flex-end',
            marginTop: '1rem',
          }}
        >
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={sync.isPending || testSnmp.isPending}
          >
            {isSync
              ? sync.isPending
                ? 'Syncing…'
                : 'Run Sync'
              : testOnly
                ? testSnmp.isPending
                  ? 'Testing…'
                  : 'Test SNMP'
                : 'Scan Network'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
