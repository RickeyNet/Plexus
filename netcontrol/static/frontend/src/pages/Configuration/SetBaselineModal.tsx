import { useMemo, useState } from 'react';

import { useInventoryGroups } from '@/api/compliance';
import {
  type ConfigSnapshot,
  useCreateConfigBaseline,
} from '@/api/configuration';
import { apiRequest } from '@/api/client';
import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';

interface Props {
  onClose: () => void;
}

export function SetBaselineModal({ onClose }: Props) {
  const { alert } = useDialogs();
  const groups = useInventoryGroups(true);
  const create = useCreateConfigBaseline();
  const [hostId, setHostId] = useState<number | null>(null);
  const [name, setName] = useState('');
  const [configText, setConfigText] = useState('');

  const hosts = useMemo(() => {
    const list: { id: number; hostname: string; ip_address: string }[] = [];
    for (const g of groups.data || []) {
      for (const h of g.hosts || []) list.push(h);
    }
    return list;
  }, [groups.data]);

  // Lazy fetch only when user clicks "Use Latest Snapshot"
  const [fillingSnapshot, setFillingSnapshot] = useState(false);

  const handleFillSnapshot = async () => {
    if (!hostId) {
      await alert('Please select a host first');
      return;
    }
    setFillingSnapshot(true);
    try {
      const snapshots = await apiRequest<ConfigSnapshot[]>(
        `/config-drift/snapshots?host_id=${hostId}&limit=1`,
      );
      if (!snapshots.length) {
        await alert('No snapshots available for this host. Capture a config first.');
        return;
      }
      const snap = await apiRequest<ConfigSnapshot>(
        `/config-drift/snapshots/${snapshots[0].id}`,
      );
      if (snap.config_text) setConfigText(snap.config_text);
    } catch (e) {
      void alert({ message: 'Failed to load snapshot: ' + (e as Error).message, variant: 'error' });
    } finally {
      setFillingSnapshot(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!hostId || !configText.trim()) return;
    create.mutate(
      { host_id: hostId, name, config_text: configText },
      {
        onSuccess: () => onClose(),
        onError: (err) => {
          void alert({ message: (err as Error).message, variant: 'error' });
        },
      },
    );
  };

  return (
    <Modal isOpen onClose={onClose} title="Set Configuration Baseline">
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label className="form-label">Host</label>
          <select
            className="form-select"
            value={hostId ?? ''}
            onChange={(e) =>
              setHostId(e.target.value ? Number(e.target.value) : null)
            }
            required
          >
            <option value="">Select a host…</option>
            {hosts.map((h) => (
              <option key={h.id} value={h.id}>
                {h.hostname} ({h.ip_address})
              </option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">Baseline Name</label>
          <input
            type="text"
            className="form-input"
            placeholder="e.g. Golden Config v1.0"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>
        <div className="form-group">
          <label className="form-label">Intended Configuration</label>
          <textarea
            className="form-textarea drift-baseline-textarea"
            placeholder="Paste the intended/golden running-config here…"
            value={configText}
            onChange={(e) => setConfigText(e.target.value)}
            required
            rows={12}
            style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}
          />
        </div>
        <div
          style={{
            display: 'flex',
            gap: '0.5rem',
            justifyContent: 'space-between',
            marginTop: '1rem',
            flexWrap: 'wrap',
          }}
        >
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            disabled={fillingSnapshot}
            onClick={handleFillSnapshot}
          >
            {fillingSnapshot ? 'Loading…' : 'Use Latest Snapshot'}
          </button>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={onClose}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={create.isPending}
            >
              {create.isPending ? 'Saving…' : 'Save Baseline'}
            </button>
          </div>
        </div>
      </form>
    </Modal>
  );
}
