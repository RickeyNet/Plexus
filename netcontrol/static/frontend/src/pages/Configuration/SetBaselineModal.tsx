import { useId, useMemo, useState } from 'react';

import { useInventoryGroups } from '@/api/compliance';
import {
  type ConfigSnapshot,
  useCreateConfigBaseline,
} from '@/api/configuration';
import { apiRequest } from '@/api/client';
import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';

interface Props {
  onClose: () => void;
}

export function SetBaselineModal({ onClose }: Props) {
  const groups = useInventoryGroups(true);
  const create = useCreateConfigBaseline();
  const [hostId, setHostId] = useState<number | null>(null);
  const [name, setName] = useState('');
  const [configText, setConfigText] = useState('');
  const [hostError, setHostError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const formId = useId();

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
    setHostError(null);
    setFormError(null);
    if (!hostId) {
      setHostError('Please select a host first');
      return;
    }
    setFillingSnapshot(true);
    try {
      const snapshots = await apiRequest<ConfigSnapshot[]>(
        `/config-drift/snapshots?host_id=${hostId}&limit=1`,
      );
      if (!snapshots.length) {
        setHostError('No snapshots available for this host. Capture a config first.');
        return;
      }
      const snap = await apiRequest<ConfigSnapshot>(
        `/config-drift/snapshots/${snapshots[0].id}`,
      );
      if (snap.config_text) setConfigText(snap.config_text);
    } catch (e) {
      setFormError('Failed to load snapshot: ' + (e as Error).message);
    } finally {
      setFillingSnapshot(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!hostId || !configText.trim()) return;
    setFormError(null);
    create.mutate(
      { host_id: hostId, name, config_text: configText },
      {
        onSuccess: () => onClose(),
        onError: (err) => setFormError((err as Error).message),
      },
    );
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title="Set Configuration Baseline"
      size="medium"
      footer={
        <>
          <button
            type="button"
            className="btn btn-secondary btn-sm modal-footer-start"
            disabled={fillingSnapshot}
            onClick={handleFillSnapshot}
          >
            {fillingSnapshot ? 'Loading…' : 'Use Latest Snapshot'}
          </button>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button
            type="submit"
            form={formId}
            className="btn btn-primary"
            disabled={create.isPending}
          >
            {create.isPending ? 'Saving…' : 'Save Baseline'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={handleSubmit}>
        {formError && <Callout tone="danger">{formError}</Callout>}
        {groups.isError && !groups.data && (
          <QueryError what="inventory groups" query={groups} />
        )}
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-host`}>Host</label>
          <select
            id={`${formId}-host`}
            className="form-select"
            value={hostId ?? ''}
            onChange={(e) => {
              setHostId(e.target.value ? Number(e.target.value) : null);
              setHostError(null);
            }}
            aria-invalid={!!hostError}
            required
          >
            <option value="">Select a host…</option>
            {hosts.map((h) => (
              <option key={h.id} value={h.id}>
                {h.hostname} ({h.ip_address})
              </option>
            ))}
          </select>
          <FieldError>{hostError}</FieldError>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-name`}>Baseline Name</label>
          <input
            id={`${formId}-name`}
            type="text"
            className="form-input"
            placeholder="e.g. Golden Config v1.0"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-config`}>Intended Configuration</label>
          <textarea
            id={`${formId}-config`}
            className="form-textarea drift-baseline-textarea"
            placeholder="Paste the intended/golden running-config here…"
            value={configText}
            onChange={(e) => setConfigText(e.target.value)}
            required
            rows={12}
            style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}
          />
        </div>
      </form>
    </Modal>
  );
}
