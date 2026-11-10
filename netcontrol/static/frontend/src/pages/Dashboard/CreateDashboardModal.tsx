import { useId, useState } from 'react';
import { useNavigate } from 'react-router';

import { useCreateCustomDashboard, type DashboardVariable } from '@/api/dashboard';
import { Callout } from '@/components/Callout';
import { Modal } from '@/components/Modal';

interface Props {
  isOpen: boolean;
  onClose: () => void;
}

export function CreateDashboardModal({ isOpen, onClose }: Props) {
  const formId = useId();
  const create = useCreateCustomDashboard();
  const navigate = useNavigate();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [varGroup, setVarGroup] = useState(false);
  const [varHost, setVarHost] = useState(false);
  const [saveError, setSaveError] = useState('');

  const reset = () => {
    setName('');
    setDescription('');
    setVarGroup(false);
    setVarHost(false);
    setSaveError('');
  };

  const handleClose = () => {
    reset();
    onClose();
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = name.trim();
    if (!trimmed) return;
    setSaveError('');
    const variables: DashboardVariable[] = [];
    if (varGroup) variables.push({ name: 'group', type: 'group', default: '*' });
    if (varHost) variables.push({ name: 'host', type: 'host', default: '*' });
    create.mutate(
      {
        name: trimmed,
        description: description.trim(),
        variables_json: JSON.stringify(variables),
      },
      {
        onSuccess: (created) => {
          reset();
          onClose();
          if (created?.id) navigate(`/dashboards/${created.id}`);
        },
        onError: (err) => {
          setSaveError((err as Error).message);
        },
      },
    );
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      title="Create Dashboard"
      size="small"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={handleClose}>
            Cancel
          </button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={create.isPending || !name.trim()}>
            {create.isPending ? 'Creating…' : 'Create'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={handleSubmit}>
        {saveError && <Callout tone="danger">{saveError}</Callout>}
        <div className="form-group">
          <label className="form-label">Name</label>
          <input
            type="text"
            className="form-input"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            autoFocus
          />
        </div>
        <div className="form-group">
          <label className="form-label">Description</label>
          <input
            type="text"
            className="form-input"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </div>
        <div className="form-group">
          <label className="form-label">Template Variables</label>
          <div style={{ display: 'flex', gap: '1rem' }}>
            <label>
              <input type="checkbox" checked={varGroup} onChange={(e) => setVarGroup(e.target.checked)} /> $group
            </label>
            <label>
              <input type="checkbox" checked={varHost} onChange={(e) => setVarHost(e.target.checked)} /> $host
            </label>
          </div>
        </div>
      </form>
    </Modal>
  );
}
