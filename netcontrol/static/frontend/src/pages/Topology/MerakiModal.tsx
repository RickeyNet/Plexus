import { useEffect, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';

import { useAuthStatus } from '@/api/auth';
import {
  CloudProvider,
  MerakiBuildJob,
  MerakiOrg,
  MerakiSnapshot,
  useBuildMerakiSample,
  useDeleteMerakiOrg,
  useDeleteMerakiSnapshot,
  useMerakiBuildJob,
  useMerakiOrgs,
  useMerakiSnapshots,
  useStartMerakiBuild,
  useValidateMerakiOrg,
} from '@/api/meraki';
import { useDialogs } from '@/components/DialogProvider-context';
import { Modal } from '@/components/Modal';

import { CatoAccountFormModal } from './CatoAccountFormModal';
import { MerakiOrgFormModal } from './MerakiOrgFormModal';
import { providerLabel } from './helpers';
import {
  FALLBACK_CATO_OPTIONS,
  FALLBACK_OPTIONS,
  buildStatusBadge,
  describeProgress,
  formatWhen,
} from './merakiHelpers';

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

interface Props {
  isOpen: boolean;
  onClose: () => void;
}

export function MerakiModal({ isOpen, onClose }: Props) {
  const qc = useQueryClient();
  const { alert } = useDialogs();
  const { data: auth } = useAuthStatus();
  const isAdmin = auth?.role === 'admin';
  const canWrite = isAdmin || (auth?.feature_access ?? []).includes('topology.write');

  const orgs = useMerakiOrgs();
  const snapshots = useMerakiSnapshots();
  const startBuild = useStartMerakiBuild();
  const buildSample = useBuildMerakiSample();

  const [editing, setEditing] = useState<MerakiOrg | null>(null);
  const [adding, setAdding] = useState<CloudProvider | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  // Which integration the tracked collection talks to, for the progress text.
  const [jobProvider, setJobProvider] = useState<CloudProvider>('meraki');

  const job = useMerakiBuildJob(jobId);
  const isJobRunning = jobId !== null && !job.isError && (!job.data || job.data.status === 'running');
  const isJobSettled = jobId !== null && !isJobRunning;

  // A settled job (finished, or its record expired) means new server state:
  // the topology graph now includes the new Meraki snapshot.
  useEffect(() => {
    if (!isJobSettled) return;
    qc.invalidateQueries({ queryKey: ['meraki'] });
    qc.invalidateQueries({ queryKey: ['topology'] });
    qc.invalidateQueries({ queryKey: ['mac-tracking'] });
  }, [isJobSettled, qc]);

  const handleBuild = async (org: MerakiOrg) => {
    try {
      const started = await startBuild.mutateAsync(org.id);
      setJobProvider(org.provider);
      setJobId(started.job_id);
    } catch (err) {
      void alert({ message: `Could not start the build: ${errorText(err)}`, variant: 'error' });
    }
  };

  const handleSample = async (provider: CloudProvider) => {
    setJobId(null);
    try {
      await buildSample.mutateAsync(provider);
    } catch (err) {
      void alert({ message: `Sample build failed: ${errorText(err)}`, variant: 'error' });
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Meraki Organizations and Cato Accounts" size="large">
      <p className="text-muted" style={{ marginTop: 0, fontSize: '0.9rem' }}>
        Meraki devices are collected from the Dashboard API and merged into this topology map: sites,
        devices, LAN links, WAN uplinks and VPN tunnels, with VLANs, routes, firewall rules and port
        configuration behind each device. A Cato account adds its sites, Sockets, WAN links, the PoPs
        they connect to and the connected remote users. Collect again whenever you want a fresh picture.
      </p>

      <div
        style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end', flexWrap: 'wrap', marginBottom: '0.75rem' }}
      >
        {canWrite && (
          <>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              disabled={buildSample.isPending}
              title="Add a demo Meraki organization to the map - no API key needed"
              onClick={() => handleSample('meraki')}
            >
              {buildSample.isPending ? 'Building…' : 'Load Meraki Sample'}
            </button>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              disabled={buildSample.isPending}
              title="Add a demo Cato account to the map - no API key needed"
              onClick={() => handleSample('cato')}
            >
              {buildSample.isPending ? 'Building…' : 'Load Cato Sample'}
            </button>
          </>
        )}
        {isAdmin && (
          <>
            <button type="button" className="btn btn-primary btn-sm" onClick={() => setAdding('meraki')}>
              Add Meraki Organization
            </button>
            <button type="button" className="btn btn-primary btn-sm" onClick={() => setAdding('cato')}>
              Add Cato Account
            </button>
          </>
        )}
      </div>

      {orgs.isPending && <div className="loading">Loading organizations…</div>}
      {orgs.error && (
        <div className="error">
          <strong>Failed to load organizations:</strong> {orgs.error.message}
        </div>
      )}
      {orgs.data && (
        <OrgTable
          orgs={orgs.data.orgs}
          isAdmin={isAdmin}
          canWrite={canWrite}
          isBuildActive={isJobRunning || startBuild.isPending}
          onBuild={handleBuild}
          onEdit={setEditing}
        />
      )}

      {isJobRunning && <BuildProgress job={job.data} provider={jobProvider} />}
      {isJobSettled && <BuildOutcome job={job.data} onDismiss={() => setJobId(null)} />}

      <h4 style={{ margin: '1.25rem 0 0.5rem' }}>Collection history</h4>
      {snapshots.isPending && <div className="loading">Loading history…</div>}
      {snapshots.error && (
        <div className="error">
          <strong>Failed to load history:</strong> {snapshots.error.message}
        </div>
      )}
      {snapshots.data && <SnapshotTable snapshots={snapshots.data.snapshots} canWrite={canWrite} />}

      {(adding ?? editing?.provider) === 'meraki' && (
        <MerakiOrgFormModal
          existing={editing}
          defaultOptions={orgs.data?.default_options ?? FALLBACK_OPTIONS}
          onClose={() => {
            setAdding(null);
            setEditing(null);
          }}
        />
      )}
      {(adding ?? editing?.provider) === 'cato' && (
        <CatoAccountFormModal
          existing={editing}
          defaultOptions={orgs.data?.cato_default_options ?? FALLBACK_CATO_OPTIONS}
          onClose={() => {
            setAdding(null);
            setEditing(null);
          }}
        />
      )}
    </Modal>
  );
}

interface OrgTableProps {
  orgs: MerakiOrg[];
  isAdmin: boolean;
  canWrite: boolean;
  isBuildActive: boolean;
  onBuild: (org: MerakiOrg) => void;
  onEdit: (org: MerakiOrg) => void;
}

function OrgTable({ orgs, isAdmin, canWrite, isBuildActive, onBuild, onEdit }: OrgTableProps) {
  if (orgs.length === 0) {
    return (
      <div className="empty-state">
        <p>
          No Meraki organizations or Cato accounts configured.{' '}
          {isAdmin
            ? 'Add one with its API key, or load a sample to preview.'
            : 'Ask an administrator to add one.'}
        </p>
      </div>
    );
  }
  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>Name</th>
          <th>Source</th>
          <th>Org / Account ID</th>
          <th>API Key</th>
          <th>Last Collection</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {orgs.map((org) => (
          <OrgRow
            key={org.id}
            org={org}
            isAdmin={isAdmin}
            canWrite={canWrite}
            isBuildActive={isBuildActive}
            onBuild={() => onBuild(org)}
            onEdit={() => onEdit(org)}
          />
        ))}
      </tbody>
    </table>
  );
}

interface OrgRowProps {
  org: MerakiOrg;
  isAdmin: boolean;
  canWrite: boolean;
  isBuildActive: boolean;
  onBuild: () => void;
  onEdit: () => void;
}

function OrgRow({ org, isAdmin, canWrite, isBuildActive, onBuild, onEdit }: OrgRowProps) {
  const { confirm, alert } = useDialogs();
  const validate = useValidateMerakiOrg();
  const remove = useDeleteMerakiOrg();

  const handleValidate = async () => {
    try {
      const result = await validate.mutateAsync(org.id);
      const visible = result.organizations.map((o) => `${o.name} (ID ${o.id})`).join('\n');
      void alert({
        message:
          visible && org.provider !== 'cato'
            ? `${result.message}\n\nVisible organizations:\n${visible}`
            : result.message,
        variant: result.ok ? undefined : 'error',
      });
    } catch (err) {
      void alert({ message: `Validation failed: ${errorText(err)}`, variant: 'error' });
    }
  };

  const handleDelete = async () => {
    if (
      !(await confirm(
        `Delete "${org.name}"?\n\nIts devices leave the topology map, and its stored API key and collection history are deleted.`,
      ))
    ) {
      return;
    }
    try {
      await remove.mutateAsync(org.id);
    } catch (err) {
      void alert({ message: `Delete failed: ${errorText(err)}`, variant: 'error' });
    }
  };

  return (
    <tr>
      <td>{org.name}</td>
      <td>
        <span className="badge">{providerLabel(org.provider)}</span>
      </td>
      <td>
        {org.org_id ? (
          <code>{org.org_id}</code>
        ) : (
          <span className="text-muted">{org.provider === 'cato' ? 'not set' : 'auto-detect'}</span>
        )}
      </td>
      <td>
        {org.has_api_key ? (
          <span className="badge badge-info">Stored</span>
        ) : (
          <span className="text-muted">None</span>
        )}
      </td>
      <td>
        {org.building ? (
          <span className="badge badge-info">Collecting…</span>
        ) : (
          <>
            <span className={buildStatusBadge(org.last_build_status)}>{org.last_build_status ?? 'never'}</span>{' '}
            <span className="text-muted">{org.last_build_at ? formatWhen(org.last_build_at) : ''}</span>
            {org.last_build_message && (
              <div className="text-muted" style={{ fontSize: '0.85em' }}>{org.last_build_message}</div>
            )}
          </>
        )}
      </td>
      <td>
        <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap' }}>
          {canWrite && (
            <button
              type="button"
              className="btn btn-sm btn-primary"
              disabled={!org.has_api_key || org.building || isBuildActive}
              title={
                org.has_api_key
                  ? `Collect from ${providerLabel(org.provider)} and update the map`
                  : 'No API key stored'
              }
              onClick={onBuild}
            >
              Collect Now
            </button>
          )}
          {isAdmin && (
            <>
              <button
                type="button"
                className="btn btn-sm btn-secondary"
                disabled={!org.has_api_key || validate.isPending}
                onClick={handleValidate}
              >
                {validate.isPending ? '…' : 'Test Key'}
              </button>
              <button type="button" className="btn btn-sm btn-secondary" onClick={onEdit}>
                Edit
              </button>
              <button
                type="button"
                className="btn btn-sm btn-danger"
                disabled={remove.isPending || org.building}
                onClick={handleDelete}
              >
                Del
              </button>
            </>
          )}
        </div>
      </td>
    </tr>
  );
}

function BuildProgress({ job, provider }: { job: MerakiBuildJob | undefined; provider: CloudProvider }) {
  const { label, percent } = describeProgress(job);
  return (
    <div className="card" style={{ marginTop: '1rem', padding: '1rem' }}>
      <strong>Collecting from {providerLabel(provider)}…</strong>
      <div className="text-muted" style={{ margin: '0.35rem 0' }}>{label}</div>
      <div
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={percent ?? undefined}
        style={{ height: 8, borderRadius: 4, background: 'var(--bg-secondary)', overflow: 'hidden' }}
      >
        <div
          style={{
            height: '100%',
            width: `${percent ?? 100}%`,
            opacity: percent === null ? 0.35 : 1,
            background: 'var(--primary, var(--success))',
            transition: 'width 0.4s ease',
          }}
        />
      </div>
      <div className="text-muted" style={{ fontSize: '0.85em', marginTop: '0.35rem' }}>
        {provider === 'cato'
          ? 'A Cato account takes a few queries, sent slowly to stay inside the Cato API rate limits.'
          : 'Large organizations take several minutes: Meraki limits the API to 10 requests per second.'}{' '}
        You can close this dialog; the map updates when collection finishes.
      </div>
    </div>
  );
}

function BuildOutcome({ job, onDismiss }: { job: MerakiBuildJob | undefined; onDismiss: () => void }) {
  // No job record means the poll failed: the server restarted or the record
  // expired. The build may still have produced a snapshot.
  const failed = !job || job.status === 'failed';
  const result = job?.result;
  return (
    <div className={failed ? 'error' : 'card'} style={{ marginTop: '1rem', padding: '0.75rem 1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: '1rem', alignItems: 'center' }}>
        <div>
          {!job && <>Lost track of the collection job. Check the history below for its result.</>}
          {job && failed && (
            <>
              <strong>Collection failed:</strong> {job.error ?? 'Unknown error'}
            </>
          )}
          {!failed && result && (
            <>
              <strong>Map updated</strong> in {result.duration_seconds}s: {result.summary.sites ?? 0} sites,{' '}
              {result.summary.devices ?? 0} devices, {result.summary.vpn_tunnels ?? 0} VPN tunnels.
              {result.warning_count > 0 && (
                <span style={{ color: 'var(--warning)' }}>
                  {' '}
                  {result.warning_count} collection warning(s) - see Report in the HTML map for details.
                </span>
              )}
            </>
          )}
        </div>
        <button type="button" className="btn btn-sm btn-ghost" onClick={onDismiss}>
          Dismiss
        </button>
      </div>
    </div>
  );
}

function SnapshotTable({ snapshots, canWrite }: { snapshots: MerakiSnapshot[]; canWrite: boolean }) {
  const { confirm, alert } = useDialogs();
  const remove = useDeleteMerakiSnapshot();

  if (snapshots.length === 0) {
    return <p className="text-muted">Nothing collected yet.</p>;
  }

  // The map always shows the newest snapshot of each organization.
  const newestByOrg = new Map<number, number>();
  for (const s of snapshots) {
    if ((newestByOrg.get(s.org_ref) ?? 0) < s.id) newestByOrg.set(s.org_ref, s.id);
  }

  const handleDelete = async (snapshot: MerakiSnapshot) => {
    if (!(await confirm(`Delete the ${formatWhen(snapshot.created_at)} collection of "${snapshot.org_name}"?`))) return;
    try {
      await remove.mutateAsync(snapshot.id);
    } catch (err) {
      void alert({ message: `Delete failed: ${errorText(err)}`, variant: 'error' });
    }
  };

  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>Organization / Account</th>
          <th>Collected</th>
          <th>Sites</th>
          <th>Devices</th>
          <th>VPN Tunnels</th>
          <th>Warnings</th>
          <th />
        </tr>
      </thead>
      <tbody>
        {snapshots.map((s) => (
          <tr key={s.id}>
            <td>
              {s.org_name}{' '}
              {newestByOrg.get(s.org_ref) === s.id && <span className="badge badge-success">on map</span>}
            </td>
            <td>
              {formatWhen(s.created_at)}
              {s.built_by && <span className="text-muted"> by {s.built_by}</span>}
            </td>
            <td>{s.summary.sites ?? 0}</td>
            <td>{s.summary.devices ?? 0}</td>
            <td>{s.summary.vpn_tunnels ?? 0}</td>
            <td>
              {s.warning_count > 0 ? (
                <span className="badge badge-warning">{s.warning_count}</span>
              ) : (
                <span className="text-muted">0</span>
              )}
            </td>
            <td>
              {canWrite && (
                <button
                  type="button"
                  className="btn btn-sm btn-danger"
                  disabled={remove.isPending}
                  onClick={() => handleDelete(s)}
                >
                  Del
                </button>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
