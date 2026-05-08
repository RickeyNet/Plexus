import { useEffect, useState } from 'react';

import { useUpdateProfile } from '@/api/auth';
import { Modal } from './Modal';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  username: string;
  initialDisplayName: string;
}

export function EditProfileModal({ isOpen, onClose, username, initialDisplayName }: Props) {
  const [displayName, setDisplayName] = useState(initialDisplayName);
  const [error, setError] = useState<string | null>(null);
  const update = useUpdateProfile();

  useEffect(() => {
    if (isOpen) {
      setDisplayName(initialDisplayName);
      setError(null);
    }
  }, [isOpen, initialDisplayName]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await update.mutateAsync({ display_name: displayName });
      onClose();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Edit Profile">
      <form onSubmit={onSubmit}>
        <div className="form-group">
          <label className="form-label">Username</label>
          <input
            type="text"
            className="form-input"
            value={username}
            disabled
            style={{ opacity: 0.6 }}
          />
          <small style={{ color: 'var(--text-muted)' }}>Username cannot be changed</small>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="profile-display-name">Display Name</label>
          <input
            id="profile-display-name"
            type="text"
            className="form-input"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            required
          />
        </div>
        {error && (
          <div style={{ color: 'var(--danger)', fontSize: '0.85rem', marginBottom: '0.5rem' }}>{error}</div>
        )}
        <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end', marginTop: '1rem' }}>
          <button type="button" className="btn btn-secondary" onClick={onClose} disabled={update.isPending}>
            Cancel
          </button>
          <button type="submit" className="btn btn-primary" disabled={update.isPending}>
            {update.isPending ? 'Saving…' : 'Save'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
