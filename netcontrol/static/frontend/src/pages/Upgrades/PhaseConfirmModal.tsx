import { useEffect, useMemo, useState } from 'react';

import {
  type UpgradePhase,
  useExecuteUpgradePhase,
} from '@/api/upgrades';
import { Modal } from '@/components/Modal';

import { phaseLabel } from './helpers';

interface Props {
  campaignId: number;
  phase: UpgradePhase;
  schedule: boolean;
  selectedDeviceIds: number[];
  explicitDeviceIds?: number[];
  onClose: () => void;
}

function pad(n: number) {
  return String(n).padStart(2, '0');
}

function defaultScheduleValue(): { min: string; value: string } {
  const min = new Date(Date.now() + 60 * 1000);
  min.setSeconds(0, 0);
  const def = new Date(Date.now() + 30 * 60 * 1000);
  def.setSeconds(0, 0);
  const fmt = (d: Date) =>
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(
      d.getHours(),
    )}:${pad(d.getMinutes())}`;
  return { min: fmt(min), value: fmt(def) };
}

export function PhaseConfirmModal({
  campaignId,
  phase,
  schedule,
  selectedDeviceIds,
  explicitDeviceIds,
  onClose,
}: Props) {
  const execute = useExecuteUpgradePhase();
  const deviceIds = explicitDeviceIds ?? selectedDeviceIds;
  const targetText =
    deviceIds.length > 0
      ? `${deviceIds.length} selected device(s)`
      : 'all campaign devices';

  const initialSchedule = useMemo(defaultScheduleValue, []);
  const [scheduledAt, setScheduledAt] = useState(initialSchedule.value);
  const [error, setError] = useState<string | null>(null);
  const timezone =
    Intl.DateTimeFormat().resolvedOptions().timeZone || 'local timezone';

  useEffect(() => {
    setError(null);
    execute.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const label = phaseLabel(phase);
  const isActivate = phase === 'activate';
  const title = schedule
    ? 'Schedule Reload (Activate)'
    : phase === 'verify'
      ? 'Verify Upgrade'
      : phase === 'verify_prestage'
        ? 'Re-Verify Prestage'
        : `Execute ${label}`;

  const body = schedule
    ? `Schedule the activate/reload phase for ${targetText}.`
    : isActivate
      ? `This will reload switches and cause downtime on ${targetText}. Are you sure?`
      : phase === 'verify'
        ? `Connect to ${targetText} and check the running version against the target?`
        : phase === 'verify_prestage'
          ? `Check install-add unpackaged artifacts on ${targetText}?`
          : `Run ${label} phase on ${targetText}?`;

  const confirmText = schedule
    ? 'Schedule Reload'
    : isActivate
      ? 'Activate & Reload'
      : phase === 'verify'
        ? 'Verify'
        : phase === 'verify_prestage'
          ? 'Run Check'
          : `Run ${label}`;

  const confirmClass = schedule || isActivate ? 'btn-danger' : 'btn-primary';

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    let scheduledIso: string | undefined;
    if (schedule) {
      const when = new Date(scheduledAt);
      if (!scheduledAt || Number.isNaN(when.getTime())) {
        setError('Choose a valid schedule time');
        return;
      }
      if (when <= new Date()) {
        setError('Schedule time must be in the future');
        return;
      }
      scheduledIso = when.toISOString();
    }

    execute.mutate(
      {
        campaignId,
        payload: {
          phase,
          device_ids: deviceIds,
          ...(scheduledIso ? { scheduled_at: scheduledIso } : {}),
        },
      },
      {
        onSuccess: () => onClose(),
        onError: (err) => setError((err as Error).message),
      },
    );
  };

  return (
    <Modal isOpen onClose={onClose} title={title}>
      <form onSubmit={handleSubmit}>
        <p style={{ margin: '0 0 0.75rem', opacity: 0.85 }}>{body}</p>
        {schedule && (
          <div className="form-group">
            <label className="form-label">Run At ({timezone})</label>
            <input
              type="datetime-local"
              className="form-input"
              required
              min={initialSchedule.min}
              value={scheduledAt}
              onChange={(e) => setScheduledAt(e.target.value)}
            />
            <p style={{ fontSize: '0.85em', opacity: 0.75, marginTop: '0.5rem' }}>
              Devices will reload at this time, which can cause downtime.
            </p>
          </div>
        )}
        {error && (
          <p style={{ color: 'var(--danger)', marginTop: '0.5rem' }}>{error}</p>
        )}
        <div
          style={{
            display: 'flex',
            justifyContent: 'flex-end',
            gap: '0.5rem',
            marginTop: '1rem',
          }}
        >
          <button
            type="button"
            className="btn btn-secondary"
            onClick={onClose}
            disabled={execute.isPending}
          >
            Cancel
          </button>
          <button
            type="submit"
            className={`btn ${confirmClass}`}
            disabled={execute.isPending}
          >
            {execute.isPending ? 'Working…' : confirmText}
          </button>
        </div>
      </form>
    </Modal>
  );
}
