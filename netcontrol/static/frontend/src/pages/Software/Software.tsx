import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';

import { PageHelp } from '@/components/PageHelp';
import { useDialogs } from '@/components/DialogProvider-context';
import { useAuthStatus } from '@/api/auth';
import {
  type SoftwareAdvisory,
  type SoftwareAlert,
  type SoftwareDevice,
  type SoftwarePlatformSpread,
  type SoftwareVersionChange,
  useAcknowledgeSoftwareAlert,
  useDeleteSoftwareAdvisory,
  usePsirtSyncJob,
  useRefreshSoftware,
  useSoftwareOverview,
  useStartPsirtSync,
} from '@/api/software';

import { AdvisoryModal } from './AdvisoryModal';
import { DeviceHistoryModal } from './DeviceHistoryModal';
import { ImportAdvisoriesModal } from './ImportAdvisoriesModal';
import { SettingsModal } from './SettingsModal';
import { barWidth, formatTime, severityBadgeClass, severityLabel, sourceLabel } from './helpers';

type ModalState =
  | { kind: 'none' }
  | { kind: 'advisory'; advisory: SoftwareAdvisory | null }
  | { kind: 'import' }
  | { kind: 'settings' }
  | { kind: 'history'; device: SoftwareDevice };

const PLATFORM_FALLBACK = 'Other';

export function Software() {
  const qc = useQueryClient();
  const { alert, confirm } = useDialogs();
  const { data: auth } = useAuthStatus();
  const isAdmin = auth?.role === 'admin';
  const canWrite = isAdmin || (auth?.feature_access ?? []).includes('software.write');

  const [platform, setPlatform] = useState('');
  const [source, setSource] = useState('');
  const [search, setSearch] = useState('');
  const [modal, setModal] = useState<ModalState>({ kind: 'none' });
  const [syncJobId, setSyncJobId] = useState<string | null>(null);

  const overview = useSoftwareOverview(platform, source, search);
  const refresh = useRefreshSoftware();
  const acknowledge = useAcknowledgeSoftwareAlert();
  const deleteAdvisory = useDeleteSoftwareAdvisory();
  const startSync = useStartPsirtSync();
  const syncJob = usePsirtSyncJob(syncJobId);

  const data = overview.data;
  const summary = data?.summary;
  const devices = data?.devices ?? [];
  const spread = data?.platforms ?? [];
  const alerts = data?.alerts ?? [];
  const advisories = data?.advisories ?? [];
  const changes = data?.changes ?? [];
  const catalog = data?.platform_catalog ?? [];
  const severities = data?.severities ?? ['critical', 'high', 'medium', 'low', 'info'];
  const settings = data?.settings;
  const platformLabel = (key: string) => catalog.find((p) => p.key === key)?.label ?? key ?? PLATFORM_FALLBACK;
  const sources = Object.keys(summary?.sources ?? {});

  // The sync finished since the last render: refresh what it changed.
  const [seenJobStatus, setSeenJobStatus] = useState<string>('');
  const jobStatus = syncJob.data?.status ?? '';
  if (syncJobId && jobStatus && jobStatus !== 'running' && seenJobStatus !== `${syncJobId}:${jobStatus}`) {
    setSeenJobStatus(`${syncJobId}:${jobStatus}`);
    qc.invalidateQueries({ queryKey: ['software-overview'] });
  }

  const handleRefresh = async () => {
    try {
      const res = await refresh.mutateAsync();
      if (res.changed > 0 || res.alerts.new > 0) {
        void alert(
          `${res.devices} devices tracked; ${res.changed} version change${res.changed === 1 ? '' : 's'}, ` +
            `${res.alerts.new} new alert${res.alerts.new === 1 ? '' : 's'}.`,
        );
      }
    } catch (err) {
      void alert({ message: (err as Error).message, variant: 'error' });
    }
  };

  const handleSync = async () => {
    try {
      const res = await startSync.mutateAsync();
      setSyncJobId(res.job_id);
    } catch (err) {
      void alert({ message: (err as Error).message, variant: 'error' });
    }
  };

  const handleAcknowledge = async (a: SoftwareAlert) => {
    try {
      await acknowledge.mutateAsync(a.id);
    } catch (err) {
      void alert({ message: (err as Error).message, variant: 'error' });
    }
  };

  const handleDelete = async (adv: SoftwareAdvisory) => {
    const ok = await confirm({
      message: `Delete advisory ${adv.advisory_id}? Its alerts are removed as well.`,
      confirmLabel: 'Delete',
      confirmVariant: 'danger',
    });
    if (!ok) return;
    try {
      await deleteAdvisory.mutateAsync(adv.advisory_id);
    } catch (err) {
      void alert({ message: (err as Error).message, variant: 'error' });
    }
  };

  const summaryCards = [
    { label: 'Tracked Devices', value: summary?.devices ?? 0 },
    { label: 'Platforms', value: summary?.platforms ?? 0 },
    { label: 'Distinct Versions', value: summary?.versions ?? 0 },
    {
      label: 'Behind Newest Seen',
      value: summary?.behind_newest ?? 0,
      color: (summary?.behind_newest ?? 0) > 0 ? 'var(--warning-color)' : undefined,
    },
    {
      label: 'Open Alerts',
      value: summary?.open_alerts ?? 0,
      color:
        (summary?.critical_alerts ?? 0) > 0
          ? 'var(--danger-color)'
          : (summary?.open_alerts ?? 0) > 0
            ? 'var(--warning-color)'
            : undefined,
    },
    { label: 'Advisories', value: summary?.advisories ?? 0 },
  ];

  return (
    <div>
      <div
        className="page-header"
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-end',
          gap: '1rem',
          flexWrap: 'wrap',
          marginBottom: '1rem',
        }}
      >
        <div>
          <h2 style={{ margin: 0 }}>Software Versions</h2>
          <div className="text-muted" style={{ fontSize: '0.88em', marginTop: '0.2rem' }}>
            Last refresh: {formatTime(summary?.last_refresh_at)}
            {settings?.psirt_last_sync_at ? ` · Cisco PSIRT sync: ${formatTime(settings.psirt_last_sync_at)}` : ''}
          </div>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'end' }}>
          <label>
            Platform{' '}
            <select className="form-select" value={platform} onChange={(e) => setPlatform(e.target.value)}>
              <option value="">All platforms</option>
              {spread.map((p) => (
                <option key={p.platform} value={p.platform}>
                  {p.label} ({p.device_count})
                </option>
              ))}
            </select>
          </label>
          <label>
            Source{' '}
            <select className="form-select" value={source} onChange={(e) => setSource(e.target.value)}>
              <option value="">All sources</option>
              {sources.map((s) => (
                <option key={s} value={s}>
                  {sourceLabel(s)} ({summary?.sources[s] ?? 0})
                </option>
              ))}
            </select>
          </label>
          <input
            className="form-input"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search name, model, serial, site, version"
            style={{ width: 260 }}
          />
          {canWrite && (
            <button type="button" className="btn btn-secondary" onClick={handleRefresh} disabled={refresh.isPending}>
              {refresh.isPending ? 'Refreshing…' : 'Refresh'}
            </button>
          )}
          {isAdmin && (
            <button
              type="button"
              className="btn btn-secondary"
              onClick={handleSync}
              disabled={startSync.isPending || jobStatus === 'running' || !settings?.has_psirt_secret}
              title={
                settings?.has_psirt_secret
                  ? 'Ask Cisco PSIRT about every tracked Cisco version'
                  : 'Store a Cisco PSIRT client ID and secret in Settings first'
              }
            >
              {jobStatus === 'running' ? 'Syncing PSIRT…' : 'Sync Cisco PSIRT'}
            </button>
          )}
          {isAdmin && (
            <button type="button" className="btn btn-secondary" onClick={() => setModal({ kind: 'settings' })}>
              Settings
            </button>
          )}
        </div>
      </div>

      <PageHelp
        pageKey="software"
        title="Software Versions & Vulnerability Alerts"
        text="Every software version Plexus knows - inventory hosts polled by SNMP/SSH, and the Meraki, Cato and AnyConnect devices of the latest topology collections - in one list, with the version spread per platform, a history of upgrades and downgrades, and alerts when a device runs a version an advisory names. Add advisories by hand, import them, or let Plexus ask Cisco PSIRT about every Cisco version it tracks."
      />

      {syncJobId && syncJob.data && (
        <div
          className="card"
          style={{ padding: '0.6rem 1rem', marginBottom: '1rem', display: 'flex', gap: '1rem', alignItems: 'center' }}
        >
          <strong>Cisco PSIRT sync</strong>
          {jobStatus === 'running' ? (
            <span className="text-muted">
              {syncJob.data.progress.phase ?? 'running'}
              {syncJob.data.progress.total
                ? ` · ${syncJob.data.progress.done ?? 0} / ${syncJob.data.progress.total} versions`
                : ''}
              {syncJob.data.progress.current ? ` · ${syncJob.data.progress.current}` : ''}
            </span>
          ) : (
            <span className={jobStatus === 'failed' ? 'text-danger' : 'text-muted'}>
              {jobStatus === 'failed'
                ? syncJob.data.error ?? 'failed'
                : syncJob.data.result?.message ?? jobStatus}
              {jobStatus === 'partial' && syncJob.data.result?.errors?.length
                ? ` - ${syncJob.data.result.errors[0]}`
                : ''}
            </span>
          )}
          {jobStatus !== 'running' && (
            <button type="button" className="btn btn-secondary btn-sm" onClick={() => setSyncJobId(null)}>
              Dismiss
            </button>
          )}
        </div>
      )}

      <div style={{ marginBottom: '1rem' }}>
        <div
          className="stats-grid"
          style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: '1rem' }}
        >
          {summaryCards.map((card) => (
            <div key={card.label} className="stat-card">
              <div className="stat-value" style={card.color ? { color: card.color } : undefined}>
                {String(card.value)}
              </div>
              <div className="stat-label">{card.label}</div>
            </div>
          ))}
        </div>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'minmax(0, 2fr) minmax(340px, 1fr)',
          gap: '1rem',
          alignItems: 'start',
        }}
      >
        <div style={{ display: 'grid', gap: '1rem' }}>
          <DevicesCard
            devices={devices}
            loading={overview.isPending}
            filtered={Boolean(platform || source || search)}
            onHistory={(device) => setModal({ kind: 'history', device })}
          />
          <AlertsCard alerts={alerts} canWrite={canWrite} onAcknowledge={handleAcknowledge} />
        </div>
        <div style={{ display: 'grid', gap: '1rem' }}>
          <SpreadCard spread={spread} />
          <AdvisoriesCard
            advisories={advisories}
            canWrite={canWrite}
            platformLabel={platformLabel}
            onAdd={() => setModal({ kind: 'advisory', advisory: null })}
            onImport={() => setModal({ kind: 'import' })}
            onEdit={(advisory) => setModal({ kind: 'advisory', advisory })}
            onDelete={handleDelete}
          />
          <ChangesCard changes={changes} platformLabel={platformLabel} />
        </div>
      </div>

      {modal.kind === 'advisory' && (
        <AdvisoryModal
          advisory={modal.advisory}
          platforms={catalog.filter((p) => p.key !== 'other')}
          severities={severities}
          onClose={() => setModal({ kind: 'none' })}
        />
      )}
      {modal.kind === 'import' && <ImportAdvisoriesModal onClose={() => setModal({ kind: 'none' })} />}
      {modal.kind === 'settings' && settings && (
        <SettingsModal settings={settings} severities={severities} onClose={() => setModal({ kind: 'none' })} />
      )}
      {modal.kind === 'history' && (
        <DeviceHistoryModal device={modal.device} onClose={() => setModal({ kind: 'none' })} />
      )}
    </div>
  );
}

// ── Cards ──────────────────────────────────────────────────────────────────

interface DevicesCardProps {
  devices: SoftwareDevice[];
  loading: boolean;
  filtered: boolean;
  onHistory: (device: SoftwareDevice) => void;
}

function DevicesCard({ devices, loading, filtered, onHistory }: DevicesCardProps) {
  return (
    <div className="card" style={{ padding: '1rem', overflow: 'auto' }}>
      <div style={{ marginBottom: '0.75rem' }}>
        <h3 style={{ margin: 0 }}>Devices</h3>
        <div className="text-muted" style={{ fontSize: '0.88em', marginTop: '0.2rem' }}>
          {devices.length} device{devices.length === 1 ? '' : 's'}
          {filtered ? ' matching the filter' : ''}
        </div>
      </div>
      {loading ? (
        <div className="text-muted">Loading devices…</div>
      ) : devices.length === 0 ? (
        <div className="empty-state">
          <p>
            {filtered
              ? 'No device matches the filter.'
              : 'No software versions yet. Poll your inventory (SNMP enrichment stores the version) or collect a Meraki, Cato or AnyConnect topology, then Refresh.'}
          </p>
        </div>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>Device</th>
              <th>Source</th>
              <th>Platform</th>
              <th>Model</th>
              <th>Version</th>
              <th>Alerts</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d.device_key}>
                <td>
                  <div style={{ fontWeight: 600 }}>{d.name}</div>
                  <div className="text-muted" style={{ fontSize: '0.82em' }}>
                    {[d.site, d.org_name, d.serial].filter(Boolean).join(' · ')}
                  </div>
                </td>
                <td>{sourceLabel(d.source)}</td>
                <td>{d.platform_label ?? d.platform}</td>
                <td>{d.model || <span className="text-muted">-</span>}</td>
                <td>
                  <span style={{ fontWeight: 600 }}>{d.version}</span>
                  {d.behind_newest && (
                    <span
                      className="badge badge-warning"
                      style={{ fontSize: '0.7em', marginLeft: '0.4rem' }}
                      title="A newer version of this platform is running elsewhere in the fleet"
                    >
                      behind
                    </span>
                  )}
                  {d.changed_at && (
                    <div className="text-muted" style={{ fontSize: '0.8em' }} title={formatTime(d.changed_at)}>
                      was {d.previous_version || '?'}
                    </div>
                  )}
                </td>
                <td>
                  {(d.alert_count ?? 0) > 0 ? (
                    <span
                      className={severityBadgeClass(d.worst_severity)}
                      title={`${d.unacknowledged_alerts ?? 0} unacknowledged`}
                    >
                      {d.alert_count} {severityLabel(d.worst_severity).toLowerCase()}
                    </span>
                  ) : (
                    <span className="text-muted">-</span>
                  )}
                </td>
                <td style={{ textAlign: 'right' }}>
                  <button type="button" className="btn btn-secondary btn-sm" onClick={() => onHistory(d)}>
                    History
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function SpreadCard({ spread }: { spread: SoftwarePlatformSpread[] }) {
  return (
    <div className="card" style={{ padding: '1rem' }}>
      <h3 style={{ margin: '0 0 0.75rem' }}>Version Spread</h3>
      {spread.length === 0 ? (
        <p className="text-muted" style={{ margin: 0 }}>
          Nothing tracked yet.
        </p>
      ) : (
        spread.map((p) => {
          const max = Math.max(...p.versions.map((v) => v.count));
          return (
            <div key={p.platform} style={{ padding: '0.6rem 0', borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.5rem', alignItems: 'baseline' }}>
                <strong>{p.label}</strong>
                <span className="text-muted" style={{ fontSize: '0.85em' }}>
                  {p.device_count} device{p.device_count === 1 ? '' : 's'}, {p.version_count} version
                  {p.version_count === 1 ? '' : 's'}
                  {p.behind_newest > 0 ? `, ${p.behind_newest} behind ${p.newest_version}` : ''}
                </span>
              </div>
              <div style={{ display: 'grid', gap: '0.25rem', marginTop: '0.4rem' }}>
                {p.versions.map((v) => (
                  <div key={v.version} style={{ display: 'grid', gridTemplateColumns: '120px 1fr 40px', gap: '0.5rem' }}>
                    <span style={{ fontWeight: v.behind_newest ? 400 : 600, fontSize: '0.9em' }}>{v.version}</span>
                    <div style={{ background: 'rgba(255,255,255,0.06)', borderRadius: 3, height: 10, alignSelf: 'center' }}>
                      <div
                        style={{
                          width: `${barWidth(v.count, max)}%`,
                          height: '100%',
                          borderRadius: 3,
                          background: v.behind_newest ? 'var(--warning)' : 'var(--success)',
                        }}
                      />
                    </div>
                    <span className="text-muted" style={{ fontSize: '0.85em', textAlign: 'right' }}>
                      {v.count}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          );
        })
      )}
    </div>
  );
}

interface AlertsCardProps {
  alerts: SoftwareAlert[];
  canWrite: boolean;
  onAcknowledge: (alert: SoftwareAlert) => void;
}

function AlertsCard({ alerts, canWrite, onAcknowledge }: AlertsCardProps) {
  const open = alerts.filter((a) => !a.acknowledged).length;
  return (
    <div className="card" style={{ padding: '1rem' }}>
      <h3 style={{ margin: '0 0 0.75rem' }}>Vulnerability Alerts</h3>
      {alerts.length === 0 ? (
        <p className="text-muted" style={{ margin: 0 }}>
          No tracked device runs a version an enabled advisory names.
        </p>
      ) : (
        <>
          <div className="text-muted" style={{ fontSize: '0.9em', marginBottom: '0.5rem' }}>
            {alerts.length} open alert{alerts.length === 1 ? '' : 's'}, {open} unacknowledged
          </div>
          {alerts.map((a) => (
            <div key={a.id} style={{ padding: '0.7rem 0', borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.75rem', alignItems: 'flex-start' }}>
                <div>
                  <span className={severityBadgeClass(a.severity)} style={{ marginRight: '0.4rem' }}>
                    {severityLabel(a.severity)}
                    {a.cvss != null ? ` ${a.cvss}` : ''}
                  </span>
                  {a.url ? (
                    <a href={a.url} target="_blank" rel="noreferrer">
                      {a.advisory_id}
                    </a>
                  ) : (
                    <strong>{a.advisory_id}</strong>
                  )}
                  <div style={{ fontSize: '0.9em', marginTop: '0.2rem' }}>{a.title}</div>
                  <div className="text-muted" style={{ fontSize: '0.85em', marginTop: '0.2rem' }}>
                    <strong>{a.device_name ?? a.device_key}</strong>
                    {a.model ? ` (${a.model})` : ''} runs {a.version ?? '?'}
                    {a.site ? ` · ${a.site}` : ''}
                    {a.fixed_versions.length > 0 ? ` · fixed in ${a.fixed_versions.slice(0, 3).join(', ')}` : ''}
                  </div>
                  {a.acknowledged && (
                    <div className="text-muted" style={{ fontSize: '0.8em' }}>
                      Acknowledged by {a.acknowledged_by || 'someone'} {formatTime(a.acknowledged_at)}
                    </div>
                  )}
                </div>
                {canWrite && !a.acknowledged && (
                  <button type="button" className="btn btn-secondary btn-sm" onClick={() => onAcknowledge(a)}>
                    Acknowledge
                  </button>
                )}
              </div>
            </div>
          ))}
        </>
      )}
    </div>
  );
}

interface AdvisoriesCardProps {
  advisories: SoftwareAdvisory[];
  canWrite: boolean;
  platformLabel: (key: string) => string;
  onAdd: () => void;
  onImport: () => void;
  onEdit: (advisory: SoftwareAdvisory) => void;
  onDelete: (advisory: SoftwareAdvisory) => void;
}

function AdvisoriesCard({ advisories, canWrite, platformLabel, onAdd, onImport, onEdit, onDelete }: AdvisoriesCardProps) {
  return (
    <div className="card" style={{ padding: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
        <h3 style={{ margin: 0 }}>Advisories</h3>
        {canWrite && (
          <div style={{ display: 'flex', gap: '0.4rem' }}>
            <button type="button" className="btn btn-secondary btn-sm" onClick={onImport}>
              Import
            </button>
            <button type="button" className="btn btn-primary btn-sm" onClick={onAdd}>
              + Add
            </button>
          </div>
        )}
      </div>
      {advisories.length === 0 ? (
        <p className="text-muted" style={{ margin: 0 }}>
          No advisories yet. Add one, import a list, or sync Cisco PSIRT.
        </p>
      ) : (
        advisories.map((adv) => (
          <div key={adv.advisory_id} style={{ padding: '0.6rem 0', borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.5rem', alignItems: 'flex-start' }}>
              <div style={{ minWidth: 0 }}>
                <span className={severityBadgeClass(adv.severity)} style={{ marginRight: '0.4rem' }}>
                  {severityLabel(adv.severity)}
                </span>
                {adv.url ? (
                  <a href={adv.url} target="_blank" rel="noreferrer">
                    {adv.advisory_id}
                  </a>
                ) : (
                  <strong>{adv.advisory_id}</strong>
                )}
                {!adv.enabled && (
                  <span className="badge badge-secondary" style={{ fontSize: '0.7em', marginLeft: '0.4rem' }}>
                    disabled
                  </span>
                )}
                <div style={{ fontSize: '0.9em', marginTop: '0.2rem' }}>{adv.title}</div>
                <div className="text-muted" style={{ fontSize: '0.82em', marginTop: '0.2rem', wordBreak: 'break-word' }}>
                  {adv.platform ? platformLabel(adv.platform) : 'Any platform'}
                  {adv.product_match ? ` · model contains "${adv.product_match}"` : ''}
                  {' · '}
                  {sourceLabel(adv.source)}
                  {' · affects '}
                  {adv.affected_versions.slice(0, 4).join(', ')}
                  {adv.affected_versions.length > 4 ? ` +${adv.affected_versions.length - 4}` : ''}
                </div>
              </div>
              {canWrite && (
                <div style={{ display: 'flex', gap: '0.3rem', flexShrink: 0 }}>
                  <button type="button" className="btn btn-secondary btn-sm" onClick={() => onEdit(adv)}>
                    Edit
                  </button>
                  <button type="button" className="btn btn-danger btn-sm" onClick={() => onDelete(adv)}>
                    Delete
                  </button>
                </div>
              )}
            </div>
          </div>
        ))
      )}
    </div>
  );
}

function ChangesCard({ changes, platformLabel }: { changes: SoftwareVersionChange[]; platformLabel: (key: string) => string }) {
  return (
    <div className="card" style={{ padding: '1rem' }}>
      <h3 style={{ margin: '0 0 0.75rem' }}>Recent Version Changes</h3>
      {changes.length === 0 ? (
        <p className="text-muted" style={{ margin: 0 }}>
          No upgrade or downgrade has been seen yet.
        </p>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>Device</th>
              <th>Change</th>
              <th>When</th>
            </tr>
          </thead>
          <tbody>
            {changes.map((c) => (
              <tr key={`${c.device_key}-${c.changed_at}`}>
                <td>
                  <div style={{ fontWeight: 600 }}>{c.name}</div>
                  <div className="text-muted" style={{ fontSize: '0.8em' }}>
                    {platformLabel(c.platform)}
                    {c.site ? ` · ${c.site}` : ''}
                  </div>
                </td>
                <td>
                  <span className="text-muted">{c.previous_version || '?'}</span> → <strong>{c.version}</strong>
                </td>
                <td style={{ whiteSpace: 'nowrap' }}>{formatTime(c.changed_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
