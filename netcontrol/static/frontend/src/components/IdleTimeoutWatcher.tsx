import { useEffect, useMemo, useRef, useState } from 'react';

import { useAuthStatus, useLogout, useSessionHeartbeat } from '@/api/auth';

const WARNING_WINDOW_SECONDS = 60;

function formatRemaining(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  const mins = Math.floor(s / 60);
  const secs = s % 60;
  return `${mins}:${secs.toString().padStart(2, '0')}`;
}

export function IdleTimeoutWatcher() {
  const auth = useAuthStatus();
  const heartbeat = useSessionHeartbeat();
  const logout = useLogout();
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));
  const loggedOutRef = useRef(false);

  const data = auth.data;

  const serverTime = data?.server_time;
  const authenticated = data?.authenticated ?? false;
  const neverExpires = data?.session_never_expires ?? false;
  const idleTimeout = data?.idle_timeout_seconds ?? 0;
  const lastActivity = data?.session_last_activity ?? 0;

  const deadline = useMemo(() => {
    if (!authenticated || neverExpires) return null;
    if (idleTimeout <= 0 || lastActivity <= 0) return null;
    return lastActivity + idleTimeout;
  }, [authenticated, neverExpires, idleTimeout, lastActivity]);

  // Advance `now` on a self-adjusting timer instead of a fixed 1s interval.
  // The countdown UI only shows inside the final WARNING_WINDOW_SECONDS, so
  // ticking every second for an entire (often hours-long) session just
  // re-renders to null. When the deadline is far off we sleep until we're
  // about to enter the warning window; only then do we tick per-second so the
  // countdown stays accurate. When there's no deadline we don't tick at all.
  //
  // `now` tracks the *server's* clock: each tick stamps local time plus the
  // client/server skew captured when the effect (re)starts. The skew is
  // computed here rather than during render because Date.now() is impure.
  useEffect(() => {
    if (!authenticated || deadline === null) return;
    const clockOffset = serverTime
      ? serverTime - Math.floor(Date.now() / 1000)
      : 0;
    let timer = 0;
    const tick = () => {
      const nowServer = Math.floor(Date.now() / 1000) + clockOffset;
      setNow(nowServer);
      const remaining = deadline - nowServer;
      const delayMs =
        remaining > WARNING_WINDOW_SECONDS
          ? Math.min(Math.max((remaining - WARNING_WINDOW_SECONDS) * 1000, 1000), 60_000)
          : 1000;
      timer = window.setTimeout(tick, delayMs);
    };
    tick();
    return () => window.clearTimeout(timer);
  }, [authenticated, deadline, serverTime]);

  const remaining = useMemo(() => {
    if (deadline === null) return Infinity;
    return deadline - now;
  }, [deadline, now]);

  useEffect(() => {
    if (!data?.authenticated || loggedOutRef.current) return;
    if (remaining === Infinity) return;
    // Don't auto-logout while a heartbeat is in flight - the server is about
    // to renew the session and racing it would sign the user out anyway.
    if (heartbeat.isPending) return;
    if (remaining <= 0) {
      loggedOutRef.current = true;
      logout.mutate(undefined, {
        onSettled: () => {
          loggedOutRef.current = false;
        },
      });
    }
  }, [remaining, data?.authenticated, logout, heartbeat.isPending]);

  useEffect(() => {
    loggedOutRef.current = false;
  }, [data?.authenticated]);

  if (!data?.authenticated) return null;
  if (deadline === null) return null;
  if (remaining > WARNING_WINDOW_SECONDS) return null;

  const expired = remaining <= 0;

  return (
    <div
      role="alertdialog"
      aria-live="assertive"
      aria-labelledby="idle-timeout-title"
      style={{
        position: 'fixed',
        top: '1rem',
        right: '1rem',
        zIndex: 9000,
        maxWidth: '22rem',
        padding: '0.75rem 1rem',
        border: '1px solid var(--border)',
        borderLeft: '4px solid var(--warning, #d97706)',
        borderRadius: '0.375rem',
        background: 'var(--surface, #1f2937)',
        boxShadow: '0 6px 24px rgba(0,0,0,0.35)',
        color: 'var(--text, #f3f4f6)',
      }}
    >
      <div
        id="idle-timeout-title"
        style={{ fontWeight: 600, marginBottom: '0.25rem' }}
      >
        {expired ? 'Session expired' : 'Session expiring soon'}
      </div>
      <div style={{ fontSize: '0.875rem', marginBottom: '0.5rem' }}>
        {expired
          ? 'You have been signed out due to inactivity.'
          : `You will be signed out in ${formatRemaining(remaining)} due to inactivity.`}
      </div>
      {!expired && (
        <button
          type="button"
          className="btn btn-sm btn-primary"
          disabled={heartbeat.isPending}
          onClick={() => heartbeat.mutate()}
        >
          {heartbeat.isPending ? 'Refreshing…' : 'Stay signed in'}
        </button>
      )}
    </div>
  );
}
