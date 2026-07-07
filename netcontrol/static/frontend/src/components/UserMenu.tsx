import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';

import { useAuthStatus } from '@/api/auth';
import { apiRequest, setCsrfToken } from '@/api/client';
import { ChangePasswordModal } from '@/components/ChangePasswordModal';
import { EditProfileModal } from '@/components/EditProfileModal';
import { Modal } from '@/components/Modal';

interface UserMenuProps {
  isOpen: boolean;
  onClose: () => void;
}

export function UserMenu({ isOpen, onClose }: UserMenuProps) {
  const qc = useQueryClient();
  const { data } = useAuthStatus();
  const [signingOut, setSigningOut] = useState(false);
  const [signOutError, setSignOutError] = useState<string | null>(null);
  const [editOpen, setEditOpen] = useState(false);
  const [pwOpen, setPwOpen] = useState(false);

  const username = data?.username ?? 'admin';
  const displayName = data?.display_name ?? username;
  const role = data?.role ?? 'admin';
  const initial = (displayName[0] ?? 'A').toUpperCase();

  const onSignOut = async () => {
    setSigningOut(true);
    setSignOutError(null);
    try {
      await apiRequest('/auth/logout', { method: 'POST' });
      // Only drop the CSRF token once the server has actually ended the
      // session. Nulling it on a failed logout left a still-live session
      // unable to send any authenticated mutation.
      setCsrfToken(null);
      onClose();
    } catch (err) {
      // Network blip / 500: keep the session and its CSRF token intact so the
      // user can retry rather than getting stuck signed-in-but-broken.
      setSignOutError(err instanceof Error ? err.message : 'Sign out failed. Please try again.');
    } finally {
      // Always re-enable the button (never leave it stuck on "Signing out…")
      // and refetch auth status — if the session was terminated server-side,
      // this flips the app to the login gate.
      setSigningOut(false);
      qc.invalidateQueries({ queryKey: ['auth', 'status'] });
    }
  };

  return (
    <>
      <Modal isOpen={isOpen} onClose={onClose} title="Account">
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1rem', padding: '1rem', background: 'var(--bg-secondary)', borderRadius: '0.5rem', border: '1px solid var(--border)' }}>
          <div style={{ width: 48, height: 48, borderRadius: '50%', background: 'var(--primary)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '1.25rem', fontWeight: 700, color: '#fff' }}>
            {initial}
          </div>
          <div>
            <div style={{ fontWeight: 600, fontSize: '1rem' }}>{displayName}</div>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>@{username}</div>
            <div style={{ marginTop: '0.25rem' }}>
              <span style={{ fontSize: '0.7rem', padding: '0.15rem 0.5rem', background: 'var(--primary-dark)', color: 'var(--text)', borderRadius: '0.25rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{role}</span>
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => {
              onClose();
              setEditOpen(true);
            }}
          >
            Edit Profile
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => {
              onClose();
              setPwOpen(true);
            }}
          >
            Change Password
          </button>
          <button className="btn btn-danger" onClick={onSignOut} disabled={signingOut}>
            {signingOut ? 'Signing out…' : 'Sign Out'}
          </button>
          {signOutError && (
            <div style={{ color: 'var(--danger)', fontSize: '0.8rem', marginTop: '0.25rem' }}>
              {signOutError}
            </div>
          )}
        </div>
      </Modal>
      <EditProfileModal
        isOpen={editOpen}
        onClose={() => setEditOpen(false)}
        username={username}
        initialDisplayName={displayName}
      />
      <ChangePasswordModal
        isOpen={pwOpen}
        onClose={() => setPwOpen(false)}
      />
    </>
  );
}
