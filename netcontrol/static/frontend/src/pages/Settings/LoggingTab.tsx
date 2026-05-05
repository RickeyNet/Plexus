import { useEffect, useState } from 'react';

import {
  SyslogConfig,
  useSyslogConfig,
  useTestSyslog,
  useUpdateSyslogConfig,
} from '@/api/settings';

const PROTOCOLS = ['udp', 'tcp'];
const FACILITIES = [
  'kern', 'user', 'mail', 'daemon', 'auth', 'syslog',
  'lpr', 'news', 'uucp', 'cron', 'authpriv', 'ftp',
  'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7',
];
const LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'];

export function LoggingTab() {
  const query = useSyslogConfig();
  const update = useUpdateSyslogConfig();
  const test = useTestSyslog();
  const [draft, setDraft] = useState<SyslogConfig | null>(null);
  const [status, setStatus] = useState<{ kind: 'success' | 'error'; message: string } | null>(null);

  useEffect(() => {
    if (query.data) setDraft(query.data);
  }, [query.data]);

  if (query.isLoading || !draft) return <p className="text-muted">Loading…</p>;
  if (query.isError)
    return (
      <div className="error">
        Failed to load syslog config: {(query.error as Error).message}
      </div>
    );

  const statusLabel = draft.active ? 'Active' : draft.enabled ? 'Configured' : 'Disabled';
  const statusBadge = draft.active ? 'badge-success' : 'badge-info';

  return (
    <div className="card" style={{ padding: '1rem' }}>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '0.75rem',
          flexWrap: 'wrap',
          gap: '0.5rem',
        }}
      >
        <h3 style={{ margin: 0 }}>Syslog Forwarding</h3>
        <span className={`badge ${statusBadge}`}>{statusLabel}</span>
      </div>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          setStatus(null);
          if (draft.enabled && !draft.host.trim()) {
            setStatus({
              kind: 'error',
              message: 'Syslog host is required when enabled',
            });
            return;
          }
          const { active, ...payload } = draft;
          void active;
          update.mutate(
            { ...payload, app_name: payload.app_name.trim() || 'plexus' },
            {
              onSuccess: (saved) => {
                setDraft(saved);
                setStatus({ kind: 'success', message: 'Syslog settings saved' });
              },
              onError: (err) =>
                setStatus({
                  kind: 'error',
                  message: `Failed to save syslog settings: ${(err as Error).message}`,
                }),
            },
          );
        }}
      >
        <label
          className="form-group"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.4rem',
          }}
        >
          <input
            type="checkbox"
            checked={draft.enabled}
            onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })}
          />
          <span>Enable Syslog Forwarding</span>
        </label>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem' }}>
          <div className="form-group" style={{ flex: '1 1 220px' }}>
            <label className="form-label">Host</label>
            <input
              className="form-input"
              value={draft.host}
              onChange={(e) => setDraft({ ...draft, host: e.target.value })}
            />
          </div>
          <div className="form-group" style={{ flex: '0 1 120px' }}>
            <label className="form-label">Port</label>
            <input
              type="number"
              min={1}
              max={65535}
              className="form-input"
              value={draft.port}
              onChange={(e) => setDraft({ ...draft, port: Number(e.target.value) })}
            />
          </div>
          <div className="form-group" style={{ flex: '0 1 140px' }}>
            <label className="form-label">Protocol</label>
            <select
              className="form-select"
              value={draft.protocol}
              onChange={(e) => setDraft({ ...draft, protocol: e.target.value })}
            >
              {PROTOCOLS.map((p) => (
                <option key={p} value={p}>
                  {p.toUpperCase()}
                </option>
              ))}
            </select>
          </div>
          <div className="form-group" style={{ flex: '0 1 160px' }}>
            <label className="form-label">Facility</label>
            <select
              className="form-select"
              value={draft.facility}
              onChange={(e) => setDraft({ ...draft, facility: e.target.value })}
            >
              {FACILITIES.map((f) => (
                <option key={f} value={f}>
                  {f}
                </option>
              ))}
            </select>
          </div>
          <div className="form-group" style={{ flex: '0 1 140px' }}>
            <label className="form-label">Level</label>
            <select
              className="form-select"
              value={draft.level}
              onChange={(e) => setDraft({ ...draft, level: e.target.value })}
            >
              {LEVELS.map((l) => (
                <option key={l} value={l}>
                  {l}
                </option>
              ))}
            </select>
          </div>
          <div className="form-group" style={{ flex: '1 1 200px' }}>
            <label className="form-label">App Name</label>
            <input
              className="form-input"
              value={draft.app_name}
              onChange={(e) => setDraft({ ...draft, app_name: e.target.value })}
            />
          </div>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem' }}>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={update.isPending}
          >
            {update.isPending ? 'Saving…' : 'Save Syslog Settings'}
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={!draft.active || test.isPending}
            title={
              !draft.active
                ? 'Save with logging enabled first'
                : 'Send a test message'
            }
            onClick={() => {
              setStatus(null);
              test.mutate(undefined, {
                onSuccess: () =>
                  setStatus({
                    kind: 'success',
                    message: 'Syslog test message sent',
                  }),
                onError: (err) =>
                  setStatus({
                    kind: 'error',
                    message: `Failed to send syslog test: ${(err as Error).message}`,
                  }),
              });
            }}
          >
            {test.isPending ? 'Testing…' : 'Send Test Message'}
          </button>
        </div>

        {status && (
          <div
            className={status.kind === 'error' ? 'error' : ''}
            style={{
              marginTop: '0.5rem',
              color: status.kind === 'error' ? undefined : 'var(--success)',
            }}
          >
            {status.message}
          </div>
        )}
      </form>
    </div>
  );
}
