import { useId, useState, type FormEvent } from 'react';

import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
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
  const formId = useId();
  const isOpen = mode != null;
  const query = useHostTemplate(mode === 'edit' ? templateId : null);
  const createMut = useCreateHostTemplate();
  const updateMut = useUpdateHostTemplate();

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [deviceTypes, setDeviceTypes] = useState('');
  const [autoApply, setAutoApply] = useState(true);
  const [nameError, setNameError] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  // Seed form fields from mode / loaded template data; re-seed when either changes.
  const [prevSeed, setPrevSeed] = useState<{ mode: typeof mode; data: typeof query.data }>({
    mode,
    data: query.data,
  });
  if (prevSeed.mode !== mode || prevSeed.data !== query.data) {
    setPrevSeed({ mode, data: query.data });
    setNameError(null);
    setSaveError(null);
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
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSaveError(null);
    if (!name.trim()) {
      setNameError('Name is required');
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
    const onError = (err: unknown) => { setSaveError((err as Error).message); };
    if (mode === 'edit' && templateId != null) {
      updateMut.mutate({ id: templateId, data }, { onSuccess: onClose, onError });
    } else {
      createMut.mutate(data, { onSuccess: onClose, onError });
    }
  }

  const pending = createMut.isPending || updateMut.isPending;
  const loading = mode === 'edit' && query.isPending;

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={mode === 'edit' ? 'Edit Host Template' : 'New Host Template'}
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          {!loading && (
            <button type="submit" form={formId} className="btn btn-primary" disabled={pending}>
              {pending ? 'Saving…' : mode === 'edit' ? 'Save' : 'Create'}
            </button>
          )}
        </>
      }
    >
      {loading ? (
        <LoadingState />
      ) : (
        <form id={formId} onSubmit={handleSubmit}>
          {saveError && <Callout tone="danger">{saveError}</Callout>}
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-name`}>Name</label>
            <input
              id={`${formId}-name`}
              className="form-input"
              value={name}
              onChange={(e) => {
                setName(e.target.value);
                setNameError(null);
              }}
              required
              aria-invalid={!!nameError}
            />
            <FieldError>{nameError}</FieldError>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-description`}>Description</label>
            <input id={`${formId}-description`} className="form-input" value={description} onChange={(e) => setDescription(e.target.value)} />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-device-types`}>Device Types (comma-separated, leave empty for all)</label>
            <input id={`${formId}-device-types`} className="form-input" value={deviceTypes} onChange={(e) => setDeviceTypes(e.target.value)} placeholder="e.g. cisco_ios, cisco_nxos" />
          </div>
          <div className="form-group">
            <label><input type="checkbox" checked={autoApply} onChange={(e) => setAutoApply(e.target.checked)} /> Auto-apply to matching devices</label>
          </div>
        </form>
      )}
    </Modal>
  );
}
