import { FormEvent, useState } from 'react';

import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';
import {
  type SoftwareSettings,
  type SoftwareSettingsPayload,
  useSaveSoftwareSettings,
  useTestPsirt,
} from '@/api/software';

import { formatTime } from './helpers';

interface Props {
  settings: SoftwareSettings;
  severities: string[];
  onClose: () => void;
}

export function SettingsModal({ settings, severities, onClose }: Props) {
  const { alert } = useDialogs();
  const save = useSaveSoftwareSettings();
  const test = useTestPsirt();

  const [refreshHours, setRefreshHours] = useState(Math.max(1, Math.round(settings.refresh_interval_seconds / 3600)));
  const [notifyEnabled, setNotifyEnabled] = useState(settings.notify_enabled);
  const [notifyMin, setNotifyMin] = useState(settings.notify_min_severity);
  const [psirtEnabled, setPsirtEnabled] = useState(settings.psirt_enabled);
  const [clientId, setClientId] = useState(settings.psirt_client_id);
  const [clientSecret, setClientSecret] = useState('');
  const [clearSecret, setClearSecret] = useState(false);
  const [psirtHours, setPsirtHours] = useState(Math.max(1, Math.round(settings.psirt_interval_seconds / 3600)));

  const payload = (): SoftwareSettingsPayload => {
    const body: SoftwareSettingsPayload = {
      refresh_interval_seconds: Math.max(300, refreshHours * 3600),
      notify_enabled: notifyEnabled,
      notify_min_severity: notifyMin,
      psirt_enabled: psirtEnabled,
      psirt_client_id: clientId.trim(),
      psirt_interval_seconds: Math.max(3600, psirtHours * 3600),
    };
    if (clearSecret) body.psirt_client_secret = '';
    else if (clientSecret) body.psirt_client_secret = clientSecret;
    return body;
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await save.mutateAsync(payload());
      onClose();
    } catch (err) {
      void alert({ message: (err as Error).message, variant: 'error' });
    }
  };

  const testLogin = async () => {
    try {
      await save.mutateAsync(payload());
      setClientSecret('');
      const res = await test.mutateAsync();
      void alert(res.message || 'Signed in to Cisco PSIRT.');
    } catch (err) {
      void alert({ message: (err as Error).message, variant: 'error' });
    }
  };

  return (
    <Modal isOpen onClose={onClose} title="Software Tracker Settings" size="large">
      <form onSubmit={submit}>
        <h4 style={{ margin: '0 0 0.5rem' }}>Refresh</h4>
        <div className="form-group">
          <label className="form-label">Refresh the tracked versions every (hours)</label>
          <input
            className="form-input"
            type="number"
            min={1}
            max={168}
            value={refreshHours}
            onChange={(e) => setRefreshHours(Number(e.target.value || 6))}
            style={{ width: 120 }}
          />
          <div className="text-muted" style={{ fontSize: '0.82em', marginTop: '0.25rem' }}>
            The tracker is also refreshed after every topology collection and by the Refresh button. Last
            refresh: {formatTime(settings.last_refresh_at)}.
          </div>
        </div>

        <h4 style={{ margin: '1rem 0 0.5rem' }}>Notifications</h4>
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
          <input type="checkbox" checked={notifyEnabled} onChange={(e) => setNotifyEnabled(e.target.checked)} />
          Send new vulnerability alerts to the notification channels (Settings → Notifications)
        </label>
        <div className="form-group">
          <label className="form-label">Only notify for severity at or above</label>
          <select
            className="form-select"
            value={notifyMin}
            onChange={(e) => setNotifyMin(e.target.value)}
            style={{ width: 160 }}
          >
            {severities.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>

        <h4 style={{ margin: '1rem 0 0.5rem' }}>Cisco PSIRT openVuln</h4>
        <p className="text-muted" style={{ fontSize: '0.88em', marginTop: 0 }}>
          Register an application on the Cisco API Console with the <em>Cisco PSIRT openVuln API</em> and enter
          its client ID and secret. Plexus asks Cisco which advisories affect every distinct IOS, IOS XE, IOS
          XR, NX-OS, ASA, FTD, FMC and FXOS version it tracks. The secret is stored encrypted and never shown
          again.
        </p>
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
          <input type="checkbox" checked={psirtEnabled} onChange={(e) => setPsirtEnabled(e.target.checked)} />
          Sync Cisco PSIRT on a schedule
        </label>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 1rem' }}>
          <div className="form-group">
            <label className="form-label">Client ID</label>
            <input
              className="form-input"
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
              maxLength={200}
              autoComplete="off"
            />
          </div>
          <div className="form-group">
            <label className="form-label">
              Client secret{' '}
              <span className="text-muted">
                {settings.has_psirt_secret ? '(stored; leave blank to keep)' : '(not stored)'}
              </span>
            </label>
            <input
              className="form-input"
              type="password"
              value={clientSecret}
              onChange={(e) => {
                setClientSecret(e.target.value);
                if (e.target.value) setClearSecret(false);
              }}
              maxLength={400}
              autoComplete="new-password"
              disabled={clearSecret}
            />
            {settings.has_psirt_secret && (
              <label
                style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.85em', marginTop: '0.3rem' }}
              >
                <input type="checkbox" checked={clearSecret} onChange={(e) => setClearSecret(e.target.checked)} />
                Remove the stored secret
              </label>
            )}
          </div>
        </div>
        <div className="form-group">
          <label className="form-label">Sync every (hours)</label>
          <input
            className="form-input"
            type="number"
            min={1}
            max={672}
            value={psirtHours}
            onChange={(e) => setPsirtHours(Number(e.target.value || 24))}
            style={{ width: 120 }}
          />
          <div className="text-muted" style={{ fontSize: '0.82em', marginTop: '0.25rem' }}>
            Last sync: {formatTime(settings.psirt_last_sync_at)}
            {settings.psirt_last_sync_status ? ` (${settings.psirt_last_sync_status}` : ''}
            {settings.psirt_last_sync_message ? `: ${settings.psirt_last_sync_message})` : settings.psirt_last_sync_status ? ')' : ''}
          </div>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end', marginTop: '1rem' }}>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={testLogin}
            disabled={save.isPending || test.isPending || !clientId.trim()}
            title="Saves the settings, then signs in to Cisco PSIRT"
          >
            {test.isPending ? 'Testing…' : 'Save & Test Login'}
          </button>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn btn-primary" disabled={save.isPending}>
            {save.isPending ? 'Saving…' : 'Save Settings'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
