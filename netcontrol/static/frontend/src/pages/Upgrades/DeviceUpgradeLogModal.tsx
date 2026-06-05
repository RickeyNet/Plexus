import { useUpgradeDeviceEvents } from '@/api/upgrades';
import { Modal } from '@/components/Modal';
import { formatLogTimestamp } from './helpers';

interface Props {
  campaignId: number;
  deviceId: number;
  ip: string;
  onClose: () => void;
}

export function DeviceUpgradeLogModal({
  campaignId,
  deviceId,
  ip,
  onClose,
}: Props) {
  const query = useUpgradeDeviceEvents(campaignId, deviceId);
  const events = query.data || [];

  return (
    <Modal isOpen onClose={onClose} title={`Upgrade Log: ${ip}`} size="large">
      {query.isPending ? (
        <p className="text-muted">Loading…</p>
      ) : query.error ? (
        <p style={{ color: 'var(--danger)' }}>
          Failed to load events: {(query.error as Error).message}
        </p>
      ) : events.length === 0 ? (
        <p style={{ opacity: 0.5 }}>No events yet for this device</p>
      ) : (
        <pre
          style={{
            background: 'var(--bg-secondary)',
            padding: '1rem',
            borderRadius: 8,
            maxHeight: 400,
            overflowY: 'auto',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.82rem',
            whiteSpace: 'pre-wrap',
            lineHeight: 1.5,
            margin: 0,
          }}
        >
          {events
            .map((ev) => {
              const ts = formatLogTimestamp(ev.timestamp);
              return `[${ts}] ${ev.message}`;
            })
            .join('\n')}
        </pre>
      )}
      <div
        style={{
          display: 'flex',
          justifyContent: 'flex-end',
          marginTop: '1rem',
        }}
      >
        <button type="button" className="btn btn-secondary" onClick={onClose}>
          Close
        </button>
      </div>
    </Modal>
  );
}
