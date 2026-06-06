import { useState, type FormEvent } from 'react';

import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';
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
  const { alert } = useDialogs();
  const isOpen = mode != null;
  const query = useGraphTree(mode === 'edit' ? treeId : null);
  const createMut = useCreateGraphTree();
  const updateMut = useUpdateGraphTree();

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');

  // Seed form fields from mode / loaded tree data; re-seed when either changes.
  const [prevSeed, setPrevSeed] = useState<{ mode: typeof mode; data: typeof query.data }>({
    mode,
    data: query.data,
  });
  if (prevSeed.mode !== mode || prevSeed.data !== query.data) {
    setPrevSeed({ mode, data: query.data });
    if (mode === 'create') {
      setName(''); setDescription('');
    } else if (mode === 'edit' && query.data) {
      setName(query.data.name ?? '');
      setDescription(query.data.description ?? '');
    }
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) {
      void alert('Name is required');
      return;
    }
    const data = { name: name.trim(), description: description.trim() };
    const onError = (err: unknown) => { void alert({ message: (err as Error).message, variant: 'error' }); };
    if (mode === 'edit' && treeId != null) {
      updateMut.mutate({ id: treeId, data }, { onSuccess: onClose, onError });
    } else {
      createMut.mutate(data, { onSuccess: onClose, onError });
    }
  }

  const pending = createMut.isPending || updateMut.isPending;

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={mode === 'edit' ? 'Edit Graph Tree' : 'New Graph Tree'}>
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
