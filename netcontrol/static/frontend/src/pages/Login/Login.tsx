import { useEffect, useState } from 'react';

import { useLogin, useRegister } from '@/api/auth';
import { ApiError } from '@/api/client';
import { StarfieldCanvas } from '@/components/StarfieldCanvas';

function errorMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    const body = err.body as { detail?: unknown } | undefined;
    if (body && typeof body.detail === 'string') return body.detail;
  }
  return (err as Error)?.message || fallback;
}

interface Props {
  // Whether self-registration is allowed (server-side flag). Off in most
  // deployments; the legacy app simply showed the link unconditionally and
  // let the API reject if disabled, so we mirror that.
  allowRegister?: boolean;
}

export function Login({ allowRegister = true }: Props) {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);

  const login = useLogin();
  const register = useRegister();

  useEffect(() => {
    setError(null);
  }, [mode]);

  async function onLogin(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await login.mutateAsync({ username, password });
    } catch (err) {
      setError(errorMessage(err, 'Invalid username or password'));
    }
  }

  async function onRegister(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (password !== confirm) {
      setError('Passwords do not match');
      return;
    }
    try {
      await register.mutateAsync({
        username,
        password,
        display_name: displayName || undefined,
      });
    } catch (err) {
      setError(errorMessage(err, 'Registration failed'));
    }
  }

  const pending = login.isPending || register.isPending;

  return (
    <div className="login-screen">
      <div className="space-depth space-depth-login" aria-hidden="true">
        <div className="space-nebula nebula-a"></div>
        <div className="space-nebula nebula-b"></div>
        <div className="space-nebula nebula-c"></div>
        <div className="space-vignette"></div>
      </div>
      <StarfieldCanvas className="login-particles" baseCount={110} />
      <div className="login-card">
        <div className="login-orb" aria-hidden="true" />
        <h1 className="login-title">Plexus</h1>
        <p className="login-subtitle">Network Automation Hub</p>

        {mode === 'login' ? (
          <form onSubmit={onLogin}>
            <div className="form-group">
              <label className="form-label" htmlFor="login-username">Username</label>
              <input
                id="login-username"
                type="text"
                className="form-input"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                autoComplete="username"
                autoFocus
              />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="login-password">Password</label>
              <input
                id="login-password"
                type="password"
                className="form-input"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                autoComplete="current-password"
              />
            </div>
            {error && <div className="login-error">{error}</div>}
            <button type="submit" className="btn btn-primary login-btn" disabled={pending}>
              {pending ? 'Signing in…' : 'Sign In'}
            </button>
          </form>
        ) : (
          <form onSubmit={onRegister}>
            <div className="form-group">
              <label className="form-label" htmlFor="register-username">Username</label>
              <input
                id="register-username"
                type="text"
                className="form-input"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                minLength={3}
                autoComplete="username"
                autoFocus
              />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="register-display-name">Display Name</label>
              <input
                id="register-display-name"
                type="text"
                className="form-input"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                placeholder="Optional"
                autoComplete="name"
              />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="register-password">Password</label>
              <input
                id="register-password"
                type="password"
                className="form-input"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                minLength={8}
                autoComplete="new-password"
              />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="register-confirm">Confirm Password</label>
              <input
                id="register-confirm"
                type="password"
                className="form-input"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                required
                minLength={8}
                autoComplete="new-password"
              />
            </div>
            {error && <div className="login-error">{error}</div>}
            <button type="submit" className="btn btn-primary login-btn" disabled={pending}>
              {pending ? 'Creating account…' : 'Create Account'}
            </button>
          </form>
        )}

        {allowRegister && (
          <div style={{ marginTop: '1rem', textAlign: 'center' }}>
            {mode === 'login' ? (
              <>
                <span style={{ color: 'var(--text-muted)' }}>Don't have an account?</span>
                <button
                  type="button"
                  className="btn-link"
                  style={{
                    color: 'var(--primary-light)',
                    marginLeft: '0.25rem',
                    background: 'none',
                    border: 'none',
                    padding: 0,
                    cursor: 'pointer',
                    textDecoration: 'underline',
                  }}
                  onClick={() => setMode('register')}
                >
                  Register
                </button>
              </>
            ) : (
              <>
                <span style={{ color: 'var(--text-muted)' }}>Already have an account?</span>
                <button
                  type="button"
                  className="btn-link"
                  style={{
                    color: 'var(--primary-light)',
                    marginLeft: '0.25rem',
                    background: 'none',
                    border: 'none',
                    padding: 0,
                    cursor: 'pointer',
                    textDecoration: 'underline',
                  }}
                  onClick={() => setMode('login')}
                >
                  Sign In
                </button>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
