import { useEffect, useState, type FormEvent } from 'react';

import { Modal } from '@/components/Modal';
import {
  useCreateTemplate,
  useTemplate,
  useUpdateTemplate,
} from '@/api/jobs';

interface Props {
  mode: 'create' | 'edit' | null;
  templateId: number | null;
  onClose: () => void;
}

export function TemplateFormModal({ mode, templateId, onClose }: Props) {
  const isOpen = mode != null;
  const detailQuery = useTemplate(mode === 'edit' ? templateId : null);
  const createMut = useCreateTemplate();
  const updateMut = useUpdateTemplate();

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [content, setContent] = useState('');

  useEffect(() => {
    if (mode === 'create') {
      setName(''); setDescription(''); setContent('');
    } else if (mode === 'edit' && detailQuery.data) {
      setName(detailQuery.data.name ?? '');
      setDescription(detailQuery.data.description ?? '');
      setContent(detailQuery.data.content ?? '');
    }
  }, [mode, detailQuery.data]);

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim() || !content.trim()) {
      alert('Name and content are required');
      return;
    }
    const data = { name: name.trim(), content, description: description.trim() };
    const onError = (err: unknown) => alert((err as Error).message);
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
