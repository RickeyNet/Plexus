import { useEffect, useState, type FormEvent } from 'react';

import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';
import {
  useCreateTemplate,
  useTemplate,
  useUpdateTemplate,
} from '@/api/jobs';

// Mirrors the device_type strings the driver registry accepts (see
// netcontrol/drivers/*).  '' is the generic body applied to any host
// whose vendor has no specific variant.  A vendor-specific row lets
// one logical template (by name) carry the right SNMPv3 syntax per
// platform; jobs resolve the matching body per host automatically.
const TEMPLATE_DEVICE_TYPES: { value: string; label: string }[] = [
  { value: '', label: 'Generic (all vendors)' },
  { value: 'cisco_ios', label: 'Cisco IOS' },
  { value: 'cisco_xe', label: 'Cisco IOS-XE' },
  { value: 'cisco_nxos', label: 'Cisco NX-OS' },
  { value: 'cisco_xr', label: 'Cisco IOS-XR' },
  { value: 'arista_eos', label: 'Arista EOS' },
  { value: 'juniper_junos', label: 'Juniper Junos' },
  { value: 'paloalto_panos', label: 'Palo Alto PAN-OS' },
  { value: 'fortinet', label: 'Fortinet FortiOS' },
];

interface Props {
  mode: 'create' | 'edit' | null;
  templateId: number | null;
  onClose: () => void;
}

export function TemplateFormModal({ mode, templateId, onClose }: Props) {
  const { alert } = useDialogs();
  const isOpen = mode != null;
  const detailQuery = useTemplate(mode === 'edit' ? templateId : null);
  const createMut = useCreateTemplate();
  const updateMut = useUpdateTemplate();

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [content, setContent] = useState('');
  const [deviceType, setDeviceType] = useState('');

  useEffect(() => {
    if (mode === 'create') {
      setName(''); setDescription(''); setContent(''); setDeviceType('');
    } else if (mode === 'edit' && detailQuery.data) {
      setName(detailQuery.data.name ?? '');
      setDescription(detailQuery.data.description ?? '');
      setContent(detailQuery.data.content ?? '');
      setDeviceType(detailQuery.data.device_type ?? '');
    }
  }, [mode, detailQuery.data]);

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim() || !content.trim()) {
      void alert('Name and content are required');
      return;
    }
    const data = {
      name: name.trim(),
      content,
      description: description.trim(),
      device_type: deviceType,
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
    <Modal isOpen={isOpen} onClose={onClose} title={mode === 'edit' ? 'Edit Template' : 'New Template'} size="large">
      {mode === 'edit' && detailQuery.isPending ? (
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
            <label className="form-label">Vendor</label>
            <select
              className="form-input"
              value={deviceType}
              onChange={(e) => setDeviceType(e.target.value)}
            >
              {TEMPLATE_DEVICE_TYPES.map((dt) => (
                <option key={dt.value || 'generic'} value={dt.value}>{dt.label}</option>
              ))}
            </select>
            <small className="text-muted">
              Generic applies to any device. Pick a vendor to create a
              variant of this template name; jobs send each host the body
              matching its platform (falling back to the generic body).
            </small>
          </div>
          <div className="form-group">
            <label className="form-label">Config Content</label>
            <textarea
              className="form-input"
              value={content}
              onChange={(e) => setContent(e.target.value)}
              spellCheck={false}
              wrap="off"
              required
              style={{ minHeight: 280, fontFamily: 'monospace', fontSize: '0.85rem' }}
            />
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '1rem' }}>
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
