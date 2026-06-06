import { useEffect, useState, type FormEvent } from 'react';

import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';
import {
  useCreateHostTemplate,
  useHostTemplate,
  useUpdateHostTemplate,
} from '@/api/graphTemplates';

interface Props {
  mode: 'create' | 'edit' | null;
  templateId: number | null;
  onClose: () => void;
}

export function HostTemplateModal({ mode, templateId, onClose }: Props) {
  const { alert } = useDialogs();
  const isOpen = mode != null;
  const query = useHostTemplate(mode === 'edit' ? templateId : null);
  const createMut = useCreateHostTemplate();
  const updateMut = useUpdateHostTemplate();

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [deviceTypes, setDeviceTypes] = useState('');
  const [autoApply, setAutoApply] = useState(true);

  useEffect(() => {
    if (mode === 'create') {
      setName(''); setDescription(''); setDeviceTypes(''); setAutoApply(true);
    } else if (mode === 'edit' && query.data) {
      const ht = query.data;
      setName(ht.name ?? '');
      setDescription(ht.description ?? '');
      let dts: string[] = [];
      try {
        dts = JSON.parse(ht.device_types || '[]');
      } catch { /* ignore */ }
      setDeviceTypes(dts.join(', '));
      setAutoApply(!!ht.auto_apply);
    }
  }, [mode, query.data]);

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) {
      void alert('Name is required');
      return;
    }
    const dts = deviceTypes.trim()
      ? deviceTypes.split(',').map((s) => s.trim()).filter(Boolean)
      : [];
    const data = {
      name: name.trim(),
      description: description.trim(),
      device_types: JSON.stringify(dts),
      auto_apply: autoApply,
    };
    const onError = (err: unknown) => { void alert({ message: (err as Error).message, variant: 'error' }); };
    if (mode === 'edit' && templateId != null) {
      updateMut.mutate({ id: templateId, data }, { onSuccess: onClose, onError });
    } else {
      createMut.mutate(data, { onSuccess: onClose, onError });
    }
  }

  const pending = createMut.isPending || updateMut.isPending;

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={mode === 'edit' ? 'Edit Host Template' : 'New Host Template'}>
      {mode === 'edit' && query.isPending ? (
        <p className="text-muted">Loading…</p>
      ) : (
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Name</label>
            <input className="form-input" value={name} onChange={(e) => setName(e.target.value)} required />
          </div>
          <div className="form-group">
            <label className="form-label">Description</label>
            <input className="form-input" value={description} onChange={(e) => setDescription(e.target.value)} />
          </div>
          <div className="form-group">
            <label className="form-label">Device Types (comma-separated, leave empty for all)</label>
            <input className="form-input" value={deviceTypes} onChange={(e) => setDeviceTypes(e.target.value)} placeholder="e.g. cisco_ios, cisco_nxos" />
          </div>
          <div className="form-group">
            <label><input type="checkbox" checked={autoApply} onChange={(e) => setAutoApply(e.target.checked)} /> Auto-apply to matching devices</label>
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
            <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={pending}>
              {pending ? 'Saving…' : mode === 'edit' ? 'Save' : 'Create'}
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}
