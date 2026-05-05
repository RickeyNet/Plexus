import { useState } from 'react';

import { useAuthStatus } from '@/api/auth';
import { apiRequest } from '@/api/client';
import { Modal } from '@/components/Modal';

interface UserMenuProps {
  isOpen: boolean;
  onClose: () => void;
}

export function UserMenu({ isOpen, onClose }: UserMenuProps) {
  const { data } = useAuthStatus();
  const [signingOut, setSigningOut] = useState(false);

  const username = data?.username ?? 'admin';
  const displayName = data?.display_name ?? username;
  const role = data?.role ?? 'admin';
  const initial = (displayName[0] ?? 'A').toUpperCase();

  const onSignOut = async () => {
    setSigningOut(true);
    try {
      await apiRequest('/auth/logout', { method: 'POST' });
    } catch {
      // Even if the call fails (expired session etc.), legacy still redirects.
    }
    window.location.href = '/';
  };

  return (
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
        <a href="/#settings" className="btn btn-secondary" onClick={onClose}>
          Edit Profile
        </a>
        <a href="/#settings" className="btn btn-secondary" onClick={onClose}>
          Change Password
        </a>
        <button className="btn btn-danger" onClick={onSignOut} disabled={signingOut}>
          {signingOut ? 'Signing out…' : 'Sign Out'}
        </button>
      </div>
    </Modal>
  );
}
