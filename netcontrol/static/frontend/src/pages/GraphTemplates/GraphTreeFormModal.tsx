import { useId, useState, type FormEvent } from 'react';

import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import {
  useCreateGraphTree,
  useGraphTree,
  useUpdateGraphTree,
} from '@/api/graphTemplates';

interface Props {
  mode: 'create' | 'edit' | null;
  treeId: number | null;
  onClose: () => void;
}

export function GraphTreeFormModal({ mode, treeId, onClose }: Props) {
  const formId = useId();
  const isOpen = mode != null;
  const query = useGraphTree(mode === 'edit' ? treeId : null);
  const createMut = useCreateGraphTree();
  const updateMut = useUpdateGraphTree();

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [nameError, setNameError] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  // Seed form fields from mode / loaded tree data; re-seed when either changes.
  const [prevSeed, setPrevSeed] = useState<{ mode: typeof mode; data: typeof query.data }>({
    mode,
    data: query.data,
  });
  if (prevSeed.mode !== mode || prevSeed.data !== query.data) {
    setPrevSeed({ mode, data: query.data });
    setNameError(null);
    setSaveError(null);
    if (mode === 'create') {
      setName(''); setDescription('');
    } else if (mode === 'edit' && query.data) {
      setName(query.data.name ?? '');
      setDescription(query.data.description ?? '');
    }
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSaveError(null);
    if (!name.trim()) {
      setNameError('Name is required');
      return;
    }
    const data = { name: name.trim(), description: description.trim() };
    const onError = (err: unknown) => { setSaveError((err as Error).message); };
    if (mode === 'edit' && treeId != null) {
      updateMut.mutate({ id: treeId, data }, { onSuccess: onClose, onError });
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
      title={mode === 'edit' ? 'Edit Graph Tree' : 'New Graph Tree'}
      size="small"
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
            <label className="form-label">Name</label>
            <input
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
            <label className="form-label">Description</label>
            <input className="form-input" value={description} onChange={(e) => setDescription(e.target.value)} />
          </div>
        </form>
      )}
    </Modal>
  );
}
