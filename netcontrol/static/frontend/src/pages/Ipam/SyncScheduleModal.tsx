import { FormEvent, useState } from 'react';

import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';
import { type IpamSyncConfig, useUpdateIpamSyncConfig } from '@/api/ipam';

interface Props {
  config: IpamSyncConfig;
  onClose: () => void;
}

export function SyncScheduleModal({ config, onClose }: Props) {
  const { alert } = useDialogs();
  const update = useUpdateIpamSyncConfig();
  const [enabled, setEnabled] = useState(config.enabled);
  const [intervalMin, setIntervalMin] = useState(
    Math.max(5, Math.round(config.interval_seconds / 60)),
  );

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const interval_seconds = Math.max(300, intervalMin * 60);
    try {
      await update.mutateAsync({ enabled, interval_seconds });
      onClose();
    } catch (err) {
      void alert({ message: (err as Error).message, variant: 'error' });
    }
  };

  return (
    <Modal isOpen onClose={onClose} title="Sync Schedule">
      <form onSubmit={submit}>
        <label
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            marginBottom: '0.75rem',
          }}
        >
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
          />{' '}
          Enable scheduled auto-sync
        </label>
        <div className="form-group">
          <label className="form-label">Interval (minutes)</label>
          <input
            className="form-input"
            type="number"
            min={5}
            max={1440}
            value={intervalMin}
            onChange={(e) => setIntervalMin(Number(e.target.value || 30))}
            style={{ width: 120 }}
          />
        </div>
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
          <button type="submit" className="btn btn-primary" disabled={update.isPending}>
            {update.isPending ? 'Saving…' : 'Save Schedule'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
