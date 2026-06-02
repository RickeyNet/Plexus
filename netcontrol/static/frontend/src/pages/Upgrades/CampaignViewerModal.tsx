import { useEffect, useMemo, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';

import {
  type UpgradeDevice,
  type UpgradePhase,
  useCancelUpgradeCampaign,
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
  formatScheduledTime,
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

function shortImageName(image: string | null | undefined): string {
  if (!image) return '-';
  return image.split('/').pop() || image;
}

export function CampaignViewerModal({ campaignId, onClose }: Props) {
  const qc = useQueryClient();
  const query = useUpgradeCampaign(campaignId);
  const cancel = useCancelUpgradeCampaign();

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
  const [alert, setAlert] = useState<{ title: string; message: string } | null>(
    null,
  );
  const outputRef = useRef<HTMLPreElement | null>(null);

  const campaign = query.data;
  const devices = useMemo<UpgradeDevice[]>(
    () => campaign?.devices || [],
    [campaign],
  );
  const imageMap = useMemo(
    () => parseObject(campaign?.image_map) as Record<string, string>,
    [campaign],
  );

  const isRunning = Boolean(
    campaign?.is_actively_running ?? campaign?.status?.includes('running'),
  );
  const status = campaign?.status || 'created';
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

  // WebSocket for live events
  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(
      `${protocol}//${window.location.host}/ws/upgrades/${campaignId}`,
    );
    setWsState('connecting');
    setLiveLines([]);
    setLiveStatuses({});

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
          const ts = ev.timestamp ? ev.timestamp.slice(11, 19) : '';
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
        const ts = msg.timestamp ? msg.timestamp.slice(11, 19) : '';
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

  const selectByFailedPhase = (phase: ColumnPhase) => {
    const key = `${phase}_status` as const;
    setSelectedIds(
      new Set(
        devices
          .filter((d) => {
            const live = liveStatuses[d.id];
            const status = (live?.[key] as string | undefined) ?? d[key];
            return status === 'failed';
          })
          .map((d) => d.id),
      ),
    );
  };

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

            <div
              style={{
                display: 'flex',
                gap: '0.5rem',
                marginBottom: '0.75rem',
                flexWrap: 'wrap',
                alignItems: 'center',
              }}
            >
              <button
                className="btn btn-sm btn-secondary"
                onClick={() => selectAll(true)}
                disabled={isRunning}
              >
                Select All
              </button>
              <button
                className="btn btn-sm btn-secondary"
                onClick={() => selectAll(false)}
                disabled={isRunning}
              >
                Clear
              </button>
              <button
                className="btn btn-sm btn-secondary"
                onClick={() => selectByFailedPhase('transfer')}
                disabled={isRunning}
              >
                Select Transfer Failed
              </button>
              <span
                style={{
                  opacity: 0.75,
                  fontSize: '0.85em',
                  marginLeft: 'auto',
                }}
              >
                {selectedCount > 0
                  ? `${selectedCount} selected`
                  : 'No selection (runs on all devices)'}
              </span>
            </div>

            <div
              style={{
                display: 'flex',
                gap: '0.5rem',
                marginBottom: '1rem',
                flexWrap: 'wrap',
              }}
            >
              <button
                className="btn btn-secondary"
                onClick={() => requestPhase('prestage')}
                disabled={isRunning}
              >
                Run Prestage
              </button>
              <button
                className="btn btn-secondary"
                onClick={() => requestPhase('transfer')}
                disabled={isRunning}
              >
                Run Transfer
              </button>
              {transferFailedIds.length > 0 && (
                <button
                  className="btn btn-secondary"
                  onClick={() =>
                    requestPhase('transfer', false, transferFailedIds)
                  }
                  disabled={isRunning}
                >
                  Run Transfer On Failed ({transferFailedIds.length})
                </button>
              )}
              <button
                className="btn btn-danger"
                onClick={() => requestPhase('activate')}
                disabled={isRunning}
              >
                Run Activate (Reload!)
              </button>
              <button
                className="btn btn-secondary"
                onClick={() => requestPhase('activate', true)}
                disabled={isRunning}
              >
                Schedule Reload
              </button>
              <button
                className="btn btn-secondary"
                onClick={() => requestPhase('verify_prestage')}
                disabled={isRunning}
              >
                Re-Verify Prestage
              </button>
              <button
                className="btn btn-secondary"
                onClick={() => requestPhase('verify')}
                disabled={isRunning}
              >
                Verify Upgrade
              </button>
              {isRunning && !isScheduled && (
                <button
                  className="btn btn-secondary"
                  onClick={() => setConfirmCancelOpen(true)}
                  disabled={cancel.isPending}
                >
                  Cancel
                </button>
              )}
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
                            disabled={isRunning}
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
