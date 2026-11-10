import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { type SoftwareDevice, useSoftwareHistory } from '@/api/software';
import { formatBackendDateTime } from '@/lib/datetime';

import { sourceLabel } from './helpers';

interface Props {
  device: SoftwareDevice;
  onClose: () => void;
}

export function DeviceHistoryModal({ device, onClose }: Props) {
  const history = useSoftwareHistory(device.device_key);
  const rows = history.data?.history ?? [];
  return (
    <Modal
      isOpen
      onClose={onClose}
      title={`${device.name} - version history`}
      footer={
        <button type="button" className="btn btn-secondary" onClick={onClose}>
          Close
        </button>
      }
    >
      <div className="text-muted" style={{ fontSize: '0.9em', marginBottom: '0.75rem' }}>
        {device.platform_label ?? device.platform} · {device.model || 'unknown model'} ·{' '}
        {sourceLabel(device.source)}
        {device.site ? ` · ${device.site}` : ''}
        {device.serial ? ` · ${device.serial}` : ''}
      </div>
      <div style={{ marginBottom: '0.75rem' }}>
        Running <strong>{device.version}</strong>
        {device.raw_version && device.raw_version !== device.version ? (
          <span className="text-muted"> (reported as {device.raw_version})</span>
        ) : null}
        , first seen {formatBackendDateTime(device.first_seen, 'Never')}.
      </div>
      {history.isPending ? (
        <LoadingState text="Loading history…" />
      ) : rows.length === 0 ? (
        <EmptyState compact message="No history recorded yet." />
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>Version</th>
              <th>Seen from</th>
              <th>Until</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row, i) => (
              <tr key={`${row.version}-${row.seen_from}-${i}`}>
                <td style={{ fontWeight: row.seen_until ? 400 : 600 }}>{row.version}</td>
                <td>{formatBackendDateTime(row.seen_from, 'Never')}</td>
                <td>{row.seen_until ? formatBackendDateTime(row.seen_until, 'Never') : 'now'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Modal>
  );
}
