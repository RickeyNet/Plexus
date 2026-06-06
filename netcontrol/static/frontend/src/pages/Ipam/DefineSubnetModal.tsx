import { FormEvent, useState } from 'react';

import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';
import { useCreateIpamPrefix } from '@/api/ipam';

interface Props {
  onClose: () => void;
}

export function DefineSubnetModal({ onClose }: Props) {
  const { alert } = useDialogs();
  const create = useCreateIpamPrefix();
  const [subnet, setSubnet] = useState('');
  const [description, setDescription] = useState('');
  const [vrf, setVrf] = useState('');

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!subnet.trim()) {
      void alert('Subnet CIDR is required.');
      return;
    }
    try {
      await create.mutateAsync({
        subnet: subnet.trim(),
        description: description.trim(),
        vrf: vrf.trim(),
      });
      onClose();
    } catch (err) {
      void alert({ message: (err as Error).message, variant: 'error' });
    }
  };

  return (
    <Modal isOpen onClose={onClose} title="Define a Subnet">
      <form onSubmit={submit}>
        <div className="form-group">
          <label className="form-label">
            CIDR <span className="text-muted">(e.g. 192.168.10.0/24)</span>
          </label>
          <input
            className="form-input"
            value={subnet}
            onChange={(e) => setSubnet(e.target.value)}
            required
            placeholder="10.0.0.0/24"
          />
        </div>
        <div className="form-group">
          <label className="form-label">
            Description <span className="text-muted">(optional)</span>
          </label>
          <input
            className="form-input"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            maxLength={255}
            placeholder="e.g. Server VLAN"
          />
        </div>
        <div className="form-group">
          <label className="form-label">
            VRF <span className="text-muted">(optional)</span>
          </label>
          <input
            className="form-input"
            value={vrf}
            onChange={(e) => setVrf(e.target.value)}
            maxLength={120}
            placeholder="global"
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
          <button type="submit" className="btn btn-primary" disabled={create.isPending}>
            {create.isPending ? 'Saving…' : 'Add Subnet'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
