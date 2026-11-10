import { useId, useState, type FormEvent } from 'react';

import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';
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
  { value: 'aruba_aoscx', label: 'Aruba AOS-CX' },
  { value: 'aruba_osswitch', label: 'Aruba AOS-Switch / HP ProCurve' },
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
  const formId = useId();
  const isOpen = mode != null;
  const detailQuery = useTemplate(mode === 'edit' ? templateId : null);
  const createMut = useCreateTemplate();
  const updateMut = useUpdateTemplate();

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [content, setContent] = useState('');
  const [deviceType, setDeviceType] = useState('');
  const [errors, setErrors] = useState<{ name?: string; content?: string }>({});
  const [saveError, setSaveError] = useState<string | null>(null);

  const [prevMode, setPrevMode] = useState(mode);
  const [prevData, setPrevData] = useState(detailQuery.data);
  if (mode !== prevMode || detailQuery.data !== prevData) {
    setPrevMode(mode);
    setPrevData(detailQuery.data);
    setErrors({});
    setSaveError(null);
    if (mode === 'create') {
      setName(''); setDescription(''); setContent(''); setDeviceType('');
    } else if (mode === 'edit' && detailQuery.data) {
      setName(detailQuery.data.name ?? '');
      setDescription(detailQuery.data.description ?? '');
      setContent(detailQuery.data.content ?? '');
      setDeviceType(detailQuery.data.device_type ?? '');
    }
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSaveError(null);
    const nextErrors = {
      name: name.trim() ? undefined : 'Name is required',
      content: content.trim() ? undefined : 'Content is required',
    };
    setErrors(nextErrors);
    if (nextErrors.name || nextErrors.content) return;
    const data = {
      name: name.trim(),
      content,
      description: description.trim(),
      device_type: deviceType,
    };
    const onError = (err: unknown) => { setSaveError((err as Error).message); };
    if (mode === 'edit' && templateId != null) {
      updateMut.mutate({ id: templateId, data }, { onSuccess: onClose, onError });
    } else {
      createMut.mutate(data, { onSuccess: onClose, onError });
    }
  }

  const pending = createMut.isPending || updateMut.isPending;
  const loadFailed = mode === 'edit' && detailQuery.error != null && !detailQuery.data;
  const loading = mode === 'edit' && detailQuery.isPending;

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={mode === 'edit' ? 'Edit Template' : 'New Template'}
      size="medium"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          {!loading && !loadFailed && (
            <button type="submit" form={formId} className="btn btn-primary" disabled={pending}>
              {pending ? 'Saving…' : mode === 'edit' ? 'Save' : 'Create'}
            </button>
          )}
        </>
      }
    >
      {loadFailed ? (
        <QueryError what="template" query={detailQuery} />
      ) : loading ? (
        <LoadingState />
      ) : (
        <form id={formId} onSubmit={handleSubmit}>
          {saveError && <Callout tone="danger">{saveError}</Callout>}
          <div className="form-group">
            <label className="form-label">Name</label>
            <input
              className="form-input"
              value={name}
              onChange={(e) => { setName(e.target.value); setErrors((p) => ({ ...p, name: undefined })); }}
              aria-invalid={!!errors.name}
              required
            />
            <FieldError>{errors.name}</FieldError>
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
              onChange={(e) => { setContent(e.target.value); setErrors((p) => ({ ...p, content: undefined })); }}
              aria-invalid={!!errors.content}
              spellCheck={false}
              wrap="off"
              required
              style={{ minHeight: 280, fontFamily: 'monospace', fontSize: '0.85rem' }}
            />
            <FieldError>{errors.content}</FieldError>
          </div>
        </form>
      )}
    </Modal>
  );
}
