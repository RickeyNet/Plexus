import { useState } from 'react';

import { useChangePassword } from '@/api/auth';
import { Modal } from './Modal';

interface Props {
  isOpen: boolean;
  // When forced (must_change_password), the modal cannot be dismissed -
  // onClose is ignored until the change succeeds.
  forced?: boolean;
  onClose: () => void;
  onSuccess?: () => void;
}

export function ChangePasswordModal({ isOpen, onClose, onSuccess, forced = false }: Props) {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const change = useChangePassword();

  const [prevIsOpen, setPrevIsOpen] = useState(isOpen);
  // Reset the form whenever the modal transitions open.
  if (isOpen !== prevIsOpen) {
    setPrevIsOpen(isOpen);
    if (isOpen) {
      setCurrent('');
      setNext('');
      setConfirm('');
      setError(null);
    }
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (next !== confirm) {
      setError('New passwords do not match');
      return;
    }
    if (next === current) {
      setError('New password must be different from your current password');
      return;
    }
    if (next.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }
    try {
      await change.mutateAsync({ current_password: current, new_password: next });
      onSuccess?.();
      onClose();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  // When forced, intercept onClose so backdrop/Esc don't dismiss.
  const handleClose = forced ? () => {} : onClose;

  return (
    <Modal isOpen={isOpen} onClose={handleClose} title={forced ? 'Password Change Required' : 'Change Password'}>
      {forced && (
        <p style={{ color: 'var(--text-muted)', marginTop: 0, marginBottom: '1rem' }}>
          You must change the default password before continuing.
        </p>
      )}
      <form onSubmit={onSubmit}>
        <div className="form-group">
          <label className="form-label" htmlFor="cp-current">Current Password</label>
          <input
            id="cp-current"
            type="password"
            className="form-input"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            required
            autoComplete="current-password"
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="cp-new">New Password</label>
          <input
            id="cp-new"
            type="password"
            className="form-input"
            value={next}
            onChange={(e) => setNext(e.target.value)}
            required
            minLength={8}
            autoComplete="new-password"
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="cp-confirm">Confirm New Password</label>
          <input
            id="cp-confirm"
            type="password"
            className="form-input"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            required
            minLength={8}
            autoComplete="new-password"
          />
        </div>
        {error && (
          <div style={{ color: 'var(--danger)', fontSize: '0.85rem', marginBottom: '0.5rem' }}>{error}</div>
        )}
        <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end', marginTop: '1rem' }}>
          {!forced && (
            <button type="button" className="btn btn-secondary" onClick={onClose} disabled={change.isPending}>
              Cancel
            </button>
          )}
          <button type="submit" className="btn btn-primary" disabled={change.isPending}>
            {change.isPending ? 'Changing…' : 'Change Password'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
