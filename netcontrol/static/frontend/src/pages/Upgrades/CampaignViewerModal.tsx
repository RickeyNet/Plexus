import { type ReactNode, useEffect, useMemo, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';

import {
  type UpgradeDevice,
  type UpgradeOperation,
  type UpgradePhase,
  useCancelUpgradeCampaign,
  useCancelUpgradeDevices,
  useUpgradeCampaign,
} from '@/api/upgrades';
import { Modal } from '@/components/Modal';
import { AlertDialog } from '@/components/AlertDialog';
import { ConfirmDialog } from '@/components/ConfirmDialog';

import { DeviceUpgradeLogModal } from './DeviceUpgradeLogModal';
import { PhaseConfirmModal } from './PhaseConfirmModal';
import {
  campaignStatusBadgeClass,
  campaignStatusLabel,
  formatLogTimestamp,
  formatOperationTime,
  formatScheduledTime,
  phaseLabel,
} from './helpers';

interface Props {
  campaignId: number;
  onClose: () => void;
}

interface PhaseRequest {
  phase: UpgradePhase;
  schedule: boolean;
  explicitDeviceIds?: number[];
}

interface DeviceStatusUpdate {
  device_id: number;
  prestage_status?: string;
  transfer_status?: string;
  activate_status?: string;
  verify_status?: string;
  error_message?: string | null;
}

interface UpgradeEventMsg {
  type?: string;
  campaign_id?: number;
  device_id?: number | null;
  level?: string;
  message?: string;
  host?: string;
  timestamp?: string;
  event_id?: number;
  status?: string;
  phase?: string;
  events?: UpgradeEventMsg[];
  prestage_status?: string;
  transfer_status?: string;
  activate_status?: string;
  verify_status?: string;
  error_message?: string | null;
}

type ColumnPhase = 'prestage' | 'transfer' | 'activate' | 'verify';
const PHASE_COLUMNS: ColumnPhase[] = ['prestage', 'transfer', 'activate', 'verify'];

function parseObject(value: unknown): Record<string, unknown> {
  if (typeof value === 'string') {
    try {
      return JSON.parse(value) as Record<string, unknown>;
    } catch {
      return {};
    }
  }
  if (value && typeof value === 'object') return value as Record<string, unknown>;
  return {};
}

function statusIcon(s: string | null | undefined) {
  switch (s) {
    case 'completed':
      return <span style={{ color: 'var(--success)' }}>✓</span>;
    case 'running':
      return <span style={{ color: 'var(--info)' }}>⚙</span>;
    case 'failed':
      return <span style={{ color: 'var(--danger)' }}>✗</span>;
    case 'cancelled':
      return <span style={{ opacity: 0.5 }}>∅</span>;
    default:
      return <span style={{ opacity: 0.3 }}>•</span>;
  }
}

// Capitalised, human-friendly version of a raw per-phase status token
// ('failed' → 'Failed'). Kept tiny on purpose; the raw tokens are already
// close to display-ready.
function statusLabel(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function operationBadgeClass(status: string | null | undefined): string {
  if (!status) return 'badge-secondary';
  if (status.includes('failed')) return 'badge-error';
  if (status.includes('missed') || status === 'scheduled') return 'badge-warning';
  if (status === 'running' || status.startsWith('running_')) return 'badge-info';
  if (status === 'cancelled') return 'badge-secondary';
  if (status.includes('complete')) return 'badge-success';
  return 'badge-secondary';
}

function operationStatusLabel(status: string | null | undefined): string {
  if (!status) return 'Pending';
  if (status === 'running') return 'Running';
  if (status === 'scheduled') return 'Scheduled';
  return campaignStatusLabel(status);
}

function shortImageName(image: string | null | undefined): string {
  if (!image) return '-';
  return image.split('/').pop() || image;
}

function OperationHistory({ operations }: { operations: UpgradeOperation[] }) {
  if (operations.length === 0) {
    return (
      <div className="text-muted" style={{ fontSize: '0.85em' }}>
        No operations have run for this campaign yet.
      </div>
    );
  }

  return (
    <div style={{ overflowX: 'auto' }}>
      <table className="data-table" style={{ width: '100%', fontSize: '0.84em' }}>
        <thead>
          <tr>
            <th>Operation</th>
            <th>Status</th>
            <th>Scheduled</th>
            <th>Started</th>
            <th>Completed</th>
            <th>Result</th>
            <th>Requested By</th>
          </tr>
        </thead>
        <tbody>
          {operations.map((op) => (
            <tr key={op.id}>
              <td>{phaseLabel(op.phase)}</td>
              <td>
                <span className={`badge ${operationBadgeClass(op.status)}`}>
                  {operationStatusLabel(op.status)}
                </span>
              </td>
              <td>{formatOperationTime(op.scheduled_at)}</td>
              <td>{formatOperationTime(op.started_at)}</td>
              <td>{formatOperationTime(op.completed_at)}</td>
              <td>
                <span style={{ display: 'inline-flex', gap: '0.35rem', flexWrap: 'wrap' }}>
                  <span>{op.succeeded}/{op.device_count} ok</span>
                  {op.failed > 0 && (
                    <span style={{ color: 'var(--danger)' }}>{op.failed} failed</span>
                  )}
                  {op.cancelled > 0 && (
                    <span className="text-muted">{op.cancelled} cancelled</span>
                  )}
                </span>
                {op.error_message && (
                  <div
                    title={op.error_message}
                    style={{
                      color: 'var(--danger)',
                      marginTop: '0.2rem',
                      maxWidth: 340,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {op.error_message}
                  </div>
                )}
              </td>
              <td>{op.requested_by || '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

interface PhaseCount {
  done: number;
  failed: number;
  running: number;
  total: number;
}

// Compact per-step progress pill shown in each step's header so operators can
// see where the campaign stands without reading the device table.
function StepStatus({ c }: { c: PhaseCount }) {
  if (c.total === 0) return null;
  if (c.running > 0) return <span className="badge badge-info">Running…</span>;
  if (c.done === c.total) {
    return <span className="badge badge-success">All {c.total} done</span>;
  }
  return (
    <span style={{ display: 'inline-flex', gap: '0.35rem', alignItems: 'center' }}>
      {c.failed > 0 && (
        <span className="badge badge-error">{c.failed} failed</span>
      )}
      <span className="text-muted" style={{ fontSize: '0.78em' }}>
        {c.done}/{c.total} done
      </span>
    </span>
  );
}

// One numbered step in the upgrade sequence: number badge, title, plain-English
// description, live status, and its action button(s) as children.
function PhaseStep({
  n,
  title,
  desc,
  status,
  children,
}: {
  n: number;
  title: string;
  desc: string;
  status: ReactNode;
  children: ReactNode;
}) {
  return (
    <div
      style={{
        flex: '1 1 210px',
        minWidth: 190,
        border: '1px solid var(--glass-border)',
        borderRadius: 8,
        padding: '0.7rem',
        background: 'var(--bg-secondary)',
        display: 'flex',
        flexDirection: 'column',
        gap: '0.5rem',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <span
          aria-hidden
          style={{
            width: 22,
            height: 22,
            borderRadius: '50%',
            background: 'var(--info)',
            color: '#fff',
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '0.78em',
            fontWeight: 600,
            flexShrink: 0,
          }}
        >
          {n}
        </span>
        <strong style={{ flex: 1 }}>{title}</strong>
        {status}
      </div>
      <div style={{ fontSize: '0.8em', opacity: 0.7, flex: 1 }}>{desc}</div>
      <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
        {children}
      </div>
    </div>
  );
}

export function CampaignViewerModal({ campaignId, onClose }: Props) {
  const qc = useQueryClient();
  const query = useUpgradeCampaign(campaignId);
  const cancel = useCancelUpgradeCampaign();
  const cancelDevices = useCancelUpgradeDevices();

  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [phaseReq, setPhaseReq] = useState<PhaseRequest | null>(null);
  const [deviceLog, setDeviceLog] = useState<{
    deviceId: number;
    ip: string;
  } | null>(null);
  const [liveLines, setLiveLines] = useState<string[]>([]);
  const [liveStatuses, setLiveStatuses] = useState<
    Record<number, DeviceStatusUpdate>
  >({});
  const [wsState, setWsState] = useState<'connecting' | 'open' | 'closed' | 'error'>(
    'connecting',
  );
  const [confirmCancelOpen, setConfirmCancelOpen] = useState(false);
  const [confirmDeviceCancelOpen, setConfirmDeviceCancelOpen] = useState(false);
  const [alert, setAlert] = useState<{ title: string; message: string } | null>(
    null,
  );
  const outputRef = useRef<HTMLPreElement | null>(null);

  const campaign = query.data;
  const devices = useMemo<UpgradeDevice[]>(
    () => campaign?.devices || [],
    [campaign],
  );
  const operations = useMemo<UpgradeOperation[]>(
    () => campaign?.operations || [],
    [campaign],
  );
  const imageMap = useMemo(
    () => parseObject(campaign?.image_map) as Record<string, string>,
    [campaign],
  );

  const status = campaign?.status || 'created';
  const hasActiveTask = Boolean(campaign?.is_actively_running);
  const hasRunningStatus = status.startsWith('running_');
  const isRunning = hasActiveTask || hasRunningStatus;
  const isActivateRunning = status === 'running_activate';
  const friendlyStatus = campaignStatusLabel(status);
  const statusText =
    !campaign?.is_actively_running && campaign?.status?.includes('running')
      ? `${friendlyStatus} (stale)`
      : friendlyStatus;
  // A scheduled (but not yet fired) reload keeps an armed task, so isRunning is
  // true even though nothing is executing. Detect it so we can show the reload
  // time and offer reschedule/cancel instead of the generic running controls.
  const isScheduled = status.startsWith('scheduled');
  const sched = campaign?.scheduled_at
    ? formatScheduledTime(campaign.scheduled_at)
    : null;

  const transferFailedIds = useMemo(
    () =>
      devices
        .filter((d) => d.transfer_status === 'failed')
        .map((d) => d.id),
    [devices],
  );

  // Roll up each phase column across devices (preferring live websocket status)
  // so every step can show its own progress.
  const phaseCounts = useMemo(() => {
    const make = (): PhaseCount => ({
      done: 0,
      failed: 0,
      running: 0,
      total: devices.length,
    });
    const counts: Record<ColumnPhase, PhaseCount> = {
      prestage: make(),
      transfer: make(),
      activate: make(),
      verify: make(),
    };
    for (const d of devices) {
      for (const p of PHASE_COLUMNS) {
        const key = `${p}_status` as const;
        const st = (liveStatuses[d.id]?.[key] as string | undefined) ?? d[key];
        if (st === 'completed') counts[p].done += 1;
        else if (st === 'failed') counts[p].failed += 1;
        else if (st === 'running') counts[p].running += 1;
      }
    }
    return counts;
  }, [devices, liveStatuses]);

  const activateCancelTargetCount = useMemo(
    () =>
      devices.filter((d) => {
        const status =
          (liveStatuses[d.id]?.activate_status as string | undefined) ??
          d.activate_status;
        return status === 'running' || status === 'failed';
      }).length,
    [devices, liveStatuses],
  );
  const canCancelActivateDevices =
    isActivateRunning || activateCancelTargetCount > 0;

  // Reset the live websocket-backed state whenever we switch campaigns, before
  // the effect below opens the new socket. Doing this in render (not the
  // effect) keeps the seeding setStates out of the effect body.
  const [prevCampaignId, setPrevCampaignId] = useState(campaignId);
  if (campaignId !== prevCampaignId) {
    setPrevCampaignId(campaignId);
    setWsState('connecting');
    setLiveLines([]);
    setLiveStatuses({});
  }

  // WebSocket for live events
  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(
      `${protocol}//${window.location.host}/ws/upgrades/${campaignId}`,
    );

    ws.onopen = () => setWsState('open');
    ws.onerror = () => setWsState('error');
    ws.onclose = () =>
      setWsState((prev) => (prev === 'open' ? 'closed' : prev));

    ws.onmessage = (e) => {
      let msg: UpgradeEventMsg;
      try {
        msg = JSON.parse(e.data);
      } catch {
        return;
      }
      if (!msg || typeof msg !== 'object' || msg.type === 'ping') return;

      if (msg.type === 'replay_batch' && Array.isArray(msg.events)) {
        const lines: string[] = [];
        for (const ev of msg.events) {
          if (ev.type !== 'upgrade_event') continue;
          if (typeof ev.message !== 'string' || !ev.message) continue;
          const ts = formatLogTimestamp(ev.timestamp);
          const host = ev.host ? `${ev.host}: ` : '';
          lines.push(`[${ts}] ${host}${ev.message}`);
        }
        setLiveLines(lines);
        return;
      }

      if (msg.type === 'device_status' && typeof msg.device_id === 'number') {
        const id = msg.device_id;
        setLiveStatuses((prev) => ({
          ...prev,
          [id]: {
            ...prev[id],
            ...msg,
            device_id: id,
          },
        }));
        return;
      }

      if (msg.type === 'campaign_complete') {
        // Reload campaign to get fresh device statuses + clear running flags
        qc.invalidateQueries({ queryKey: ['upgrade-campaign', campaignId] });
        qc.invalidateQueries({ queryKey: ['upgrade-campaigns'] });
        return;
      }

      if (msg.type === 'upgrade_event' && typeof msg.message === 'string') {
        const ts = formatLogTimestamp(msg.timestamp);
        const host = msg.host ? `${msg.host}: ` : '';
        setLiveLines((prev) => [...prev, `[${ts}] ${host}${msg.message}`]);
      }
    };

    return () => {
      // Detach before close so buffered messages / synthetic onclose don't
      // call setState on an unmounted/replaced effect run.
      ws.onopen = null;
      ws.onmessage = null;
      ws.onerror = null;
      ws.onclose = null;
      try {
        ws.close();
      } catch {
        /* ignore */
      }
    };
  }, [campaignId, qc]);

  // Auto-scroll live output
  useEffect(() => {
    const el = outputRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [liveLines]);

  const toggleSelect = (id: number, checked: boolean) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (checked) next.add(id);
      else next.delete(id);
      return next;
    });
  };

  const selectAll = (checked: boolean) => {
    if (!checked) {
      setSelectedIds(new Set());
      return;
    }
    setSelectedIds(new Set(devices.map((d) => d.id)));
  };

  const selectByPhaseStatus = (phase: ColumnPhase, wantedStatus: string) => {
    const key = `${phase}_status` as const;
    setSelectedIds(
      new Set(
        devices
          .filter((d) => {
            const live = liveStatuses[d.id];
            const status = (live?.[key] as string | undefined) ?? d[key];
            return status === wantedStatus;
          })
          .map((d) => d.id),
      ),
    );
  };

  // Phase·status combinations that actually exist among the current devices,
  // each with a live count. Drives the "Select by status" dropdown so it only
  // ever offers selections that match something (e.g. cancelled devices show
  // up here automatically) instead of a fixed row of buttons, some of which
  // would select nothing. 'pending' (the not-yet-started state) is omitted as
  // there's nothing actionable to select there.
  const selectableGroups = useMemo(() => {
    const groups: { phase: ColumnPhase; status: string; count: number }[] = [];
    for (const phase of PHASE_COLUMNS) {
      const key = `${phase}_status` as const;
      const counts = new Map<string, number>();
      for (const d of devices) {
        const live = liveStatuses[d.id];
        const status = (live?.[key] as string | undefined) ?? d[key];
        if (!status || status === 'pending') continue;
        counts.set(status, (counts.get(status) ?? 0) + 1);
      }
      for (const [status, count] of counts) {
        groups.push({ phase, status, count });
      }
    }
    return groups;
  }, [devices, liveStatuses]);

  const requestPhase = (
    phase: UpgradePhase,
    schedule = false,
    explicitDeviceIds?: number[],
  ) => {
    setPhaseReq({ phase, schedule, explicitDeviceIds });
  };

  const handleCancelConfirm = () => {
    cancel.mutate(campaignId, {
      onSuccess: () => setConfirmCancelOpen(false),
      onError: (e) => {
        setConfirmCancelOpen(false);
        setAlert({
          title: 'Cancel failed',
          message: (e as Error).message,
        });
      },
    });
  };

  const handleDeviceCancelConfirm = () => {
    const ids = Array.from(selectedIds);
    if (ids.length === 0) return;
    cancelDevices.mutate(
      {
        campaignId,
        payload: {
          phase: 'activate',
          device_ids: ids,
        },
      },
      {
        onSuccess: () => {
          setConfirmDeviceCancelOpen(false);
          setSelectedIds(new Set());
        },
        onError: (e) => {
          setConfirmDeviceCancelOpen(false);
          setAlert({
            title: 'Device cancel failed',
            message: (e as Error).message,
          });
        },
      },
    );
  };

  // Rescheduling means clearing the armed task (cancel) and immediately
  // reopening the schedule dialog so the operator can pick a new time. The
  // backend rejects /execute while a task is armed, so the cancel must land
  // first; we only open the dialog on success.
  const handleReschedule = () => {
    cancel.mutate(campaignId, {
      onSuccess: () => setPhaseReq({ phase: 'activate', schedule: true }),
      onError: (e) =>
        setAlert({
          title: 'Reschedule failed',
          message: (e as Error).message,
        }),
    });
  };

  const title = campaign ? `Campaign: ${campaign.name}` : 'Campaign';
  const selectedCount = selectedIds.size;
  const allSelected = devices.length > 0 && selectedCount === devices.length;
  const targetText =
    selectedCount > 0
      ? `${selectedCount} selected device${selectedCount === 1 ? '' : 's'}`
      : `all ${devices.length} devices`;

  return (
    <>
      <Modal isOpen onClose={onClose} title={title} size="large">
        {query.isPending ? (
          <p className="text-muted">Loading…</p>
        ) : query.error ? (
          <p style={{ color: 'var(--danger)' }}>
            Failed to load: {(query.error as Error).message}
          </p>
        ) : campaign ? (
          <div>
            <div style={{ marginBottom: '1rem' }}>
              <span className={`badge ${campaignStatusBadgeClass(status, isRunning)}`}>
                {statusText}
              </span>
              <span
                style={{
                  opacity: 0.7,
                  marginLeft: '0.5rem',
                  fontSize: '0.85em',
                }}
              >
                {devices.length} devices
              </span>
              {Object.entries(imageMap).map(([p, img]) => (
                <span
                  key={p}
                  className="badge badge-secondary"
                  style={{ marginLeft: '0.25rem' }}
                >
                  {p} → {shortImageName(img)}
                </span>
              ))}
            </div>

            {isScheduled && (
              <div
                style={{
                  marginBottom: '1rem',
                  padding: '0.75rem 1rem',
                  borderRadius: 8,
                  background: 'rgba(245, 158, 11, 0.12)',
                  border: '1px solid rgba(245, 158, 11, 0.35)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.75rem',
                  flexWrap: 'wrap',
                }}
              >
                <span aria-hidden style={{ fontSize: '1.3em' }}>
                  ⏰
                </span>
                <div style={{ flex: 1, minWidth: 200 }}>
                  <strong style={{ color: 'var(--warning)' }}>
                    Reload scheduled
                  </strong>
                  <div style={{ fontSize: '0.9em', opacity: 0.85 }}>
                    {sched
                      ? `Devices will reload at ${sched.absolute} (${sched.relative}). Nothing runs until then.`
                      : 'Devices will reload at the scheduled time. Nothing runs until then.'}
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <button
                    className="btn btn-sm btn-secondary"
                    onClick={handleReschedule}
                    disabled={cancel.isPending}
                  >
                    Reschedule
                  </button>
                  <button
                    className="btn btn-sm btn-danger"
                    onClick={() => setConfirmCancelOpen(true)}
                    disabled={cancel.isPending}
                  >
                    Cancel reload
                  </button>
                </div>
              </div>
            )}

            <div style={{ marginBottom: '1rem' }}>
              <h4 style={{ margin: '0 0 0.5rem' }}>Operation history</h4>
              <OperationHistory operations={operations} />
            </div>

            <div style={{ marginBottom: '1rem' }}>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  marginBottom: '0.5rem',
                  flexWrap: 'wrap',
                }}
              >
                <h4 style={{ margin: 0 }}>Upgrade steps</h4>
                <span className="text-muted" style={{ fontSize: '0.82em' }}>
                  Run in order. Each step acts on <strong>{targetText}</strong>.
                </span>
                {canCancelActivateDevices && (
                  <button
                    className="btn btn-sm btn-danger"
                    style={{ marginLeft: 'auto' }}
                    onClick={() => setConfirmDeviceCancelOpen(true)}
                    disabled={selectedCount === 0 || cancelDevices.isPending}
                  >
                    Cancel selected activate
                  </button>
                )}
                {hasActiveTask && !isScheduled && (
                  <button
                    className="btn btn-sm btn-secondary"
                    style={{ marginLeft: canCancelActivateDevices ? 0 : 'auto' }}
                    onClick={() => setConfirmCancelOpen(true)}
                    disabled={cancel.isPending}
                  >
                    Cancel running step
                  </button>
                )}
              </div>

              <div style={{ display: 'flex', gap: '0.6rem', flexWrap: 'wrap' }}>
                <PhaseStep
                  n={1}
                  title="Prestage"
                  desc="Copy the firmware image onto each device and verify it. Safe — no reboot."
                  status={<StepStatus c={phaseCounts.prestage} />}
                >
                  <button
                    className="btn btn-sm btn-primary"
                    onClick={() => requestPhase('prestage')}
                    disabled={isRunning}
                  >
                    Run prestage
                  </button>
                  <button
                    className="btn btn-sm btn-secondary"
                    onClick={() => requestPhase('verify_prestage')}
                    disabled={isRunning}
                  >
                    Re-verify
                  </button>
                </PhaseStep>

                <PhaseStep
                  n={2}
                  title="Transfer"
                  desc="Install and expand the image so it is ready to boot. Still no reboot."
                  status={<StepStatus c={phaseCounts.transfer} />}
                >
                  <button
                    className="btn btn-sm btn-primary"
                    onClick={() => requestPhase('transfer')}
                    disabled={isRunning}
                  >
                    Run transfer
                  </button>
                  {transferFailedIds.length > 0 && (
                    <button
                      className="btn btn-sm btn-secondary"
                      onClick={() =>
                        requestPhase('transfer', false, transferFailedIds)
                      }
                      disabled={isRunning}
                    >
                      Retry failed ({transferFailedIds.length})
                    </button>
                  )}
                </PhaseStep>

                <PhaseStep
                  n={3}
                  title="Activate"
                  desc="Reboot devices into the new image. Causes downtime — run now or schedule it."
                  status={<StepStatus c={phaseCounts.activate} />}
                >
                  <button
                    className="btn btn-sm btn-danger"
                    onClick={() => requestPhase('activate')}
                    disabled={isRunning}
                  >
                    Activate now (reload)
                  </button>
                  <button
                    className="btn btn-sm btn-secondary"
                    onClick={() => requestPhase('activate', true)}
                    disabled={isRunning}
                  >
                    Schedule…
                  </button>
                </PhaseStep>

                <PhaseStep
                  n={4}
                  title="Verify"
                  desc="Reconnect and confirm each device is running the target version."
                  status={<StepStatus c={phaseCounts.verify} />}
                >
                  <button
                    className="btn btn-sm btn-primary"
                    onClick={() => requestPhase('verify')}
                    disabled={isRunning}
                  >
                    Verify upgrade
                  </button>
                </PhaseStep>
              </div>
            </div>

            <div
              style={{
                display: 'flex',
                gap: '0.5rem',
                marginBottom: '0.5rem',
                flexWrap: 'wrap',
                alignItems: 'center',
                fontSize: '0.85em',
              }}
            >
              <span className="text-muted">Steps apply to:</span>
              <strong>{targetText}</strong>
              <span
                style={{
                  display: 'inline-flex',
                  gap: '0.4rem',
                  flexWrap: 'wrap',
                  marginLeft: '0.5rem',
                }}
              >
                <button
                  className="btn btn-sm btn-secondary"
                  onClick={() => selectAll(!allSelected)}
                  disabled={devices.length === 0}
                >
                  {allSelected ? 'Deselect all' : 'Select all'}
                </button>
                <select
                  className="form-select"
                  style={{ width: 'auto', padding: '0.25rem 0.5rem', fontSize: '0.85em' }}
                  value=""
                  disabled={selectableGroups.length === 0}
                  onChange={(e) => {
                    const val = e.target.value;
                    if (!val) return;
                    const [phase, status] = val.split(':') as [
                      ColumnPhase,
                      string,
                    ];
                    selectByPhaseStatus(phase, status);
                  }}
                >
                  <option value="">Select by status…</option>
                  {selectableGroups.map((g) => (
                    <option
                      key={`${g.phase}:${g.status}`}
                      value={`${g.phase}:${g.status}`}
                    >
                      {phaseLabel(g.phase)} · {statusLabel(g.status)} ({g.count})
                    </option>
                  ))}
                </select>
              </span>
            </div>

            <div style={{ overflowX: 'auto' }}>
              <table
                className="data-table"
                style={{ width: '100%', fontSize: '0.85em' }}
              >
                <thead>
                  <tr>
                    <th style={{ textAlign: 'center', width: 48 }}>Sel</th>
                    <th>Device</th>
                    <th>Model</th>
                    <th>Current</th>
                    <th>Target Image</th>
                    {PHASE_COLUMNS.map((p) => (
                      <th key={p} style={{ textAlign: 'center' }}>
                        {p.charAt(0).toUpperCase() + p.slice(1)}
                      </th>
                    ))}
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {devices.map((d) => {
                    const live = liveStatuses[d.id];
                    const errMsg =
                      live?.error_message !== undefined
                        ? live.error_message
                        : d.error_message;
                    return (
                      <tr
                        key={d.id}
                        style={{ cursor: 'pointer' }}
                        onClick={() =>
                          setDeviceLog({ deviceId: d.id, ip: d.ip_address })
                        }
                      >
                        <td
                          style={{ textAlign: 'center' }}
                          onClick={(e) => e.stopPropagation()}
                        >
                          <input
                            type="checkbox"
                            checked={selectedIds.has(d.id)}
                            onChange={(e) => toggleSelect(d.id, e.target.checked)}
                          />
                        </td>
                        <td>
                          <strong>{d.hostname || d.ip_address}</strong>
                          {d.hostname && (
                            <>
                              <br />
                              <span style={{ opacity: 0.5, fontSize: '0.9em' }}>
                                {d.ip_address}
                              </span>
                            </>
                          )}
                        </td>
                        <td>
                          <code>{d.model || '-'}</code>
                        </td>
                        <td>{d.current_version || '-'}</td>
                        <td style={{ fontSize: '0.85em' }}>
                          {shortImageName(d.target_image)}
                        </td>
                        {PHASE_COLUMNS.map((p) => {
                          const key = `${p}_status` as const;
                          const status = (live?.[key] as string | undefined) ?? d[key];
                          return (
                            <td key={p} style={{ textAlign: 'center' }}>
                              {statusIcon(status)}
                            </td>
                          );
                        })}
                        <td>
                          {errMsg ? (
                            <span
                              title={errMsg}
                              style={{
                                color: 'var(--danger)',
                                fontSize: '0.85em',
                              }}
                            >
                              {errMsg.length > 40
                                ? `${errMsg.slice(0, 40)}…`
                                : errMsg}
                            </span>
                          ) : (
                            <span style={{ opacity: 0.5 }}>
                              {d.phase || 'pending'}
                            </span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            <div style={{ marginTop: '1rem' }}>
              <h4 style={{ margin: '0 0 0.5rem' }}>
                Live Output{' '}
                <span
                  style={{
                    fontSize: '0.75em',
                    opacity: 0.6,
                    fontWeight: 400,
                  }}
                >
                  ({wsState})
                </span>
              </h4>
              <pre
                ref={outputRef}
                style={{
                  background: 'var(--bg-secondary)',
                  padding: '1rem',
                  borderRadius: 8,
                  maxHeight: 280,
                  overflowY: 'auto',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.82rem',
                  whiteSpace: 'pre-wrap',
                  lineHeight: 1.5,
                  margin: 0,
                }}
              >
                {liveLines.length === 0
                  ? wsState === 'connecting'
                    ? 'Connecting…'
                    : 'No events yet.'
                  : liveLines.join('\n')}
              </pre>
            </div>
          </div>
        ) : null}
      </Modal>

      {phaseReq && (
        <PhaseConfirmModal
          campaignId={campaignId}
          phase={phaseReq.phase}
          schedule={phaseReq.schedule}
          selectedDeviceIds={Array.from(selectedIds)}
          explicitDeviceIds={phaseReq.explicitDeviceIds}
          onClose={() => setPhaseReq(null)}
        />
      )}
      {deviceLog && (
        <DeviceUpgradeLogModal
          campaignId={campaignId}
          deviceId={deviceLog.deviceId}
          ip={deviceLog.ip}
          onClose={() => setDeviceLog(null)}
        />
      )}
      <ConfirmDialog
        isOpen={confirmCancelOpen}
        title={isScheduled ? 'Cancel scheduled reload?' : 'Cancel running phase?'}
        message={
          isScheduled
            ? sched
              ? `Cancel the reload scheduled for ${sched.absolute}? Devices will not reload until you schedule it again.`
              : 'Cancel the scheduled reload? Devices will not reload until you schedule it again.'
            : 'Cancel the running phase? Devices may be left in a partial state.'
        }
        confirmLabel={isScheduled ? 'Cancel reload' : 'Cancel phase'}
        loading={cancel.isPending}
        onCancel={() => {
          if (!cancel.isPending) setConfirmCancelOpen(false);
        }}
        onConfirm={handleCancelConfirm}
      />
      <ConfirmDialog
        isOpen={confirmDeviceCancelOpen}
        title="Cancel selected activate devices?"
        message={`Mark ${selectedCount} selected device${
          selectedCount === 1 ? '' : 's'
        } cancelled for activate. Queued devices will be skipped; a reload command already sent to a device cannot be withdrawn.`}
        confirmLabel="Cancel selected"
        loading={cancelDevices.isPending}
        onCancel={() => {
          if (!cancelDevices.isPending) setConfirmDeviceCancelOpen(false);
        }}
        onConfirm={handleDeviceCancelConfirm}
      />
      <AlertDialog
        isOpen={alert !== null}
        title={alert?.title ?? ''}
        message={alert?.message ?? ''}
        variant="error"
        onClose={() => setAlert(null)}
      />
    </>
  );
}
