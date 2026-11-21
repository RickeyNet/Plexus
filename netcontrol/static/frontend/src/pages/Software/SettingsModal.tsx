import { FormEvent, useId, useState } from 'react';

import { Callout } from '@/components/Callout';
import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';
import {
  type SoftwareSettings,
  type SoftwareSettingsPayload,
  useCveEnrichmentJob,
  useSaveSoftwareSettings,
  useStartCveEnrichment,
  useTestPsirt,
} from '@/api/software';
import { formatBackendDateTime } from '@/lib/datetime';

import { cveRunSummary } from './helpers';


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
  const [cveEnabled, setCveEnabled] = useState(settings.cve_enrichment_enabled ?? false);
  const [nvdKey, setNvdKey] = useState('');
  const [clearNvdKey, setClearNvdKey] = useState(false);
  const [nvdUrl, setNvdUrl] = useState(settings.nvd_base_url ?? '');
  const [kevUrl, setKevUrl] = useState(settings.kev_url ?? '');
  const [cveJobId, setCveJobId] = useState<string | null>(null);
  const startCve = useStartCveEnrichment();
  const cveJob = useCveEnrichmentJob(cveJobId);
  const [saveError, setSaveError] = useState<string | null>(null);
  const formId = useId();

  const payload = (): SoftwareSettingsPayload => {
    const body: SoftwareSettingsPayload = {
      refresh_interval_seconds: Math.max(300, refreshHours * 3600),
      notify_enabled: notifyEnabled,
      notify_min_severity: notifyMin,
      psirt_enabled: psirtEnabled,
      psirt_client_id: clientId.trim(),
      psirt_interval_seconds: Math.max(3600, psirtHours * 3600),
      cve_enrichment_enabled: cveEnabled,
      nvd_base_url: nvdUrl.trim(),
      kev_url: kevUrl.trim(),
    };
    if (clearSecret) body.psirt_client_secret = '';
    else if (clientSecret) body.psirt_client_secret = clientSecret;
    if (clearNvdKey) body.nvd_api_key = '';
    else if (nvdKey) body.nvd_api_key = nvdKey;
    return body;
  };

  const runEnrichment = async () => {
    setSaveError(null);
    try {
      await save.mutateAsync(payload());
      setNvdKey('');
      const job = await startCve.mutateAsync();
      setCveJobId(job.job_id);
    } catch (err) {
      setSaveError((err as Error).message);
    }
  };

  const job = cveJob.data;
  const cveRunning = job?.status === 'running' || (!job && settings.cve_running);
  const lastRun = job && job.status !== 'running'
    ? cveRunSummary(job.status, job.result?.message ?? job.error ?? '')
    : cveRunSummary(settings.cve_last_run_status, settings.cve_last_run_message);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setSaveError(null);
    try {
      await save.mutateAsync(payload());
      onClose();
    } catch (err) {
      setSaveError((err as Error).message);
    }
  };

  const testLogin = async () => {
    setSaveError(null);
    try {
      await save.mutateAsync(payload());
      setClientSecret('');
      const res = await test.mutateAsync();
      void alert(res.message || 'Signed in to Cisco PSIRT.');
    } catch (err) {
      setSaveError((err as Error).message);
    }
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title="Software Tracker Settings"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={testLogin}
            disabled={save.isPending || test.isPending || !clientId.trim()}
            title="Saves the settings, then signs in to Cisco PSIRT"
          >
            {test.isPending ? 'Testing…' : 'Save & Test Login'}
          </button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={save.isPending}>
            {save.isPending ? 'Saving…' : 'Save Settings'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={submit}>
        {saveError && <Callout tone="danger">{saveError}</Callout>}
        <h4 style={{ margin: '0 0 0.5rem' }}>Refresh</h4>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-refresh-tracked-versions`}>Refresh the tracked versions every (hours)</label>
          <input
            id={`${formId}-refresh-tracked-versions`}
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
            refresh: {formatBackendDateTime(settings.last_refresh_at, 'Never')}.
          </div>
        </div>

        <h4 style={{ margin: '1rem 0 0.5rem' }}>Notifications</h4>
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
          <input type="checkbox" checked={notifyEnabled} onChange={(e) => setNotifyEnabled(e.target.checked)} />
          Send new vulnerability alerts to the notification channels (Settings → Notifications)
        </label>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-only-notify-for`}>Only notify for severity at or above</label>
          <select
            id={`${formId}-only-notify-for`}
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
            <label className="form-label" htmlFor={`${formId}-client-id`}>Client ID</label>
            <input
              id={`${formId}-client-id`}
              className="form-input"
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
              maxLength={200}
              autoComplete="off"
            />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-client-secret`}>
              Client secret{' '}
              <span className="text-muted">
                {settings.has_psirt_secret ? '(stored; leave blank to keep)' : '(not stored)'}
              </span>
            </label>
            <input
              id={`${formId}-client-secret`}
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
          <label className="form-label" htmlFor={`${formId}-sync-every`}>Sync every (hours)</label>
          <input
            id={`${formId}-sync-every`}
            className="form-input"
            type="number"
            min={1}
            max={672}
            value={psirtHours}
            onChange={(e) => setPsirtHours(Number(e.target.value || 24))}
            style={{ width: 120 }}
          />
          <div className="text-muted" style={{ fontSize: '0.82em', marginTop: '0.25rem' }}>
            Last sync: {formatBackendDateTime(settings.psirt_last_sync_at, 'Never')}
            {settings.psirt_last_sync_status ? ` (${settings.psirt_last_sync_status}` : ''}
            {settings.psirt_last_sync_message ? `: ${settings.psirt_last_sync_message})` : settings.psirt_last_sync_status ? ')' : ''}
          </div>
        </div>

        <h4 style={{ margin: '1rem 0 0.5rem' }}>CVE enrichment (NVD and CISA KEV)</h4>
        <p className="text-muted" style={{ fontSize: '0.88em', marginTop: 0 }}>
          Looks up the CVE ids of every advisory at the NVD for the CVSS score and checks them against the CISA
          Known Exploited Vulnerabilities catalogue. Only CVE ids are sent. An advisory without a severity of its
          own gets one from the score, at least high when known exploited; a vendor&apos;s or an administrator&apos;s
          severity is kept. Needs outbound HTTPS to services.nvd.nist.gov and www.cisa.gov, or to the mirrors below.
          Without an API key NVD allows about 100 lookups per run (5 requests per 30 seconds); the rest follow on
          the next run.
        </p>
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
          <input type="checkbox" checked={cveEnabled} onChange={(e) => setCveEnabled(e.target.checked)} />
          Enrich advisories from NVD and CISA KEV (runs after the scheduled refresh)
        </label>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-nvd-key`}>
            NVD API key{' '}
            <span className="text-muted">
              {settings.has_nvd_api_key ? '(stored; leave blank to keep)' : '(optional, not stored)'}
            </span>
          </label>
          <input
            id={`${formId}-nvd-key`}
            className="form-input"
            type="password"
            value={nvdKey}
            onChange={(e) => {
              setNvdKey(e.target.value);
              if (e.target.value) setClearNvdKey(false);
            }}
            maxLength={200}
            autoComplete="new-password"
            disabled={clearNvdKey}
          />
          {settings.has_nvd_api_key && (
            <label
              style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.85em', marginTop: '0.3rem' }}
            >
              <input type="checkbox" checked={clearNvdKey} onChange={(e) => setClearNvdKey(e.target.checked)} />
              Remove the stored API key
            </label>
          )}
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 1rem' }}>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-nvd-url`}>
              NVD API URL <span className="text-muted">(blank = NVD)</span>
            </label>
            <input
              id={`${formId}-nvd-url`}
              className="form-input"
              value={nvdUrl}
              onChange={(e) => setNvdUrl(e.target.value)}
              maxLength={500}
              placeholder={settings.nvd_default_url}
            />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-kev-url`}>
              CISA KEV file URL <span className="text-muted">(blank = CISA)</span>
            </label>
            <input
              id={`${formId}-kev-url`}
              className="form-input"
              value={kevUrl}
              onChange={(e) => setKevUrl(e.target.value)}
              maxLength={500}
              placeholder={settings.kev_default_url}
            />
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={runEnrichment}
            disabled={!cveEnabled || save.isPending || startCve.isPending || cveRunning}
            title="Saves the settings, then runs the enrichment in the background"
          >
            {cveRunning ? 'Running…' : 'Save & Run Now'}
          </button>
          <span className="text-muted" style={{ fontSize: '0.82em' }}>
            {cveRunning && job?.progress?.total
              ? `Running: ${job.progress.phase ?? ''} ${job.progress.done ?? 0}/${job.progress.total}`
              : `Last run: ${formatBackendDateTime(settings.cve_last_run_at ?? '', 'Never')}${lastRun ? ` (${lastRun})` : ''}`}
          </span>
        </div>
      </form>
    </Modal>
  );
}
