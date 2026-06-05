import { FormEvent, useState } from 'react';

import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';
import {
  type InventoryGroupFull,
  type InventoryHost,
  useAddHost,
  useUpdateHost,
} from '@/api/inventory';

const DEVICE_TYPES = [
  { value: 'cisco_ios', label: 'Cisco IOS' },
  { value: 'cisco_nxos', label: 'Cisco NX-OS' },
  { value: 'cisco_asa', label: 'Cisco ASA' },
  { value: 'cisco_ftd', label: 'Cisco FTD / Firepower' },
  { value: 'icmp_only', label: 'ICMP-only (ping liveness, no SNMP/SSH)' },
];

interface Props {
  /** When set, edit mode. When null, create mode (groupId required). */
  host: (InventoryHost & { group_id: number }) | null;
  groupId: number | null;
  groups: InventoryGroupFull[];
  onClose: () => void;
}

export function HostModal({ host, groupId, groups, onClose }: Props) {
  const { alert } = useDialogs();
  const isEdit = host != null;
  const add = useAddHost();
  const update = useUpdateHost();

  const [hostname, setHostname] = useState(host?.hostname ?? '');
  const [ipAddress, setIpAddress] = useState(host?.ip_address ?? '');
  const [deviceType, setDeviceType] = useState(
    host?.device_type ?? 'cisco_ios',
  );
  const [selectedGroupId, setSelectedGroupId] = useState<number>(
    host?.group_id ?? groupId ?? groups[0]?.id ?? 0,
  );

  const isPending = add.isPending || update.isPending;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const h = hostname.trim();
    const ip = ipAddress.trim();
    if (!h || !ip) {
      void alert('Hostname and IP address are required.');
      return;
    }
    try {
      if (isEdit && host) {
        await update.mutateAsync({
          hostId: host.id,
          hostname: h,
          ip_address: ip,
          device_type: deviceType,
          group_id: selectedGroupId,
        });
      } else if (groupId != null) {
        await add.mutateAsync({
          groupId,
          hostname: h,
          ip_address: ip,
          device_type: deviceType,
        });
      }
      onClose();
    } catch (err) {
      void alert({ message: (err as Error).message, variant: 'error' });
    }
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={isEdit ? 'Edit Host' : 'Add Host'}
    >
      <form onSubmit={submit}>
        <div className="form-group">
          <label className="form-label">Hostname</label>
          <input
            className="form-input"
            value={hostname}
            onChange={(e) => setHostname(e.target.value)}
            required
            autoFocus
          />
        </div>
        <div className="form-group">
          <label className="form-label">IP Address</label>
          <input
            className="form-input"
            value={ipAddress}
            onChange={(e) => setIpAddress(e.target.value)}
            required
          />
        </div>
        <div className="form-group">
          <label className="form-label">Device Type</label>
          <select
            className="form-select"
            value={deviceType ?? 'cisco_ios'}
            onChange={(e) => setDeviceType(e.target.value)}
          >
            {DEVICE_TYPES.map((t) => (
              <option key={t.value} value={t.value}>
                {t.label}
              </option>
            ))}
          </select>
        </div>
        {isEdit && (
          <div className="form-group">
            <label className="form-label">Group</label>
            <select
              className="form-select"
              value={String(selectedGroupId)}
              onChange={(e) => setSelectedGroupId(Number(e.target.value))}
            >
              {groups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          </div>
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
          <button type="submit" className="btn btn-primary" disabled={isPending}>
            {isPending ? 'Saving…' : isEdit ? 'Save' : 'Add Host'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
