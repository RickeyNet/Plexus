import { useEffect, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router';

import { useAuthStatus } from '@/api/auth';
import { useDiscoverCloudAccount } from '@/api/cloud';
import {
  CloudAccountProvider,
  CloudProvider,
  MerakiBuildJob,
  MerakiOrg,
  MerakiSnapshot,
  TopologySource,
  useBuildMerakiSample,
  useDeleteMerakiOrg,
  useDeleteMerakiSnapshot,
  useMerakiBuildJob,
  useMerakiOrgs,
  useMerakiSnapshots,
  useSnapshotWarnings,
  useStartMerakiBuild,
  useTopologySources,
  useValidateMerakiOrg,
  isCloudAccountProvider,
} from '@/api/meraki';
import { useDialogs } from '@/components/DialogProvider-context';
import { Modal } from '@/components/Modal';

import { AppgateFormModal } from './AppgateFormModal';
import { CatoAccountFormModal } from './CatoAccountFormModal';
import { FmcFormModal } from './FmcFormModal';
import { MerakiOrgFormModal } from './MerakiOrgFormModal';
import { PanoramaFormModal } from './PanoramaFormModal';
import { providerLabel, providerScopeName } from './helpers';
import {
  FALLBACK_APPGATE_OPTIONS,
  FALLBACK_CATO_OPTIONS,
  FALLBACK_FMC_OPTIONS,
  FALLBACK_OPTIONS,
  FALLBACK_PANORAMA_OPTIONS,
  buildStatusBadge,
  describeProgress,
  formatWhen,
  sourceTypeLabel,
} from './merakiHelpers';

const CLOUD_ACCOUNTS_PATH = '/cloud-visibility';

/** Sources that are entries of the organization dialog (collected as a tracked build). */
const ORG_SOURCE_TYPES = new Set<string>(['meraki', 'cato', 'fmc', 'panorama', 'appgate']);

/** Organization sources that sign in with a user and password rather than an API key. */
const LOGIN_SOURCE_TYPES = new Set<string>(['fmc', 'panorama', 'appgate']);

function isOrgSource(source: TopologySource): boolean {
  return ORG_SOURCE_TYPES.has(source.type);
}

/** AWS accounts, Azure subscriptions and GCP projects: Cloud Visibility accounts. */
function isCloudSource(source: TopologySource): boolean {
  return isCloudAccountProvider(source.type);
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** The collection whose warnings are listed in the warnings dialog. */
interface WarningsTarget {
  snapshotId: number;
  name: string;
}

/** Opens the warnings dialog of one collection. */
type ShowWarnings = (target: WarningsTarget) => void;

function WarningsBadge({ text, onClick }: { text: string | number; onClick: (() => void) | undefined }) {
  if (!onClick) return <span className="badge badge-warning">{text}</span>;
  return (
    <button
      type="button"
      className="badge badge-warning"
      style={{ border: 'none', cursor: 'pointer' }}
      title="Show the collection warnings"
      onClick={onClick}
    >
      {text}
    </button>
  );
}

interface Props {
  isOpen: boolean;
  onClose: () => void;
  /** Starts CDP / LLDP discovery of the inventory, which has its own progress dialog. */
  onDiscoverNeighbors: () => void;
}

/** Everything that feeds the map, in one list: add, collect, history. */
export function SourcesModal({ isOpen, onClose, onDiscoverNeighbors }: Props) {
  const qc = useQueryClient();
  const { alert } = useDialogs();
  const { data: auth } = useAuthStatus();
  const isAdmin = auth?.role === 'admin';
  const canWrite = isAdmin || (auth?.feature_access ?? []).includes('topology.write');

  const sources = useTopologySources();
  const orgs = useMerakiOrgs();
  const snapshots = useMerakiSnapshots();
  const startBuild = useStartMerakiBuild();
  const buildSample = useBuildMerakiSample();
  const discoverCloud = useDiscoverCloudAccount();

  const [menu, setMenu] = useState<'add' | 'sample' | null>(null);
  const [editing, setEditing] = useState<MerakiOrg | null>(null);
  const [adding, setAdding] = useState<CloudProvider | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  // Which integration the tracked collection talks to, for the progress text.
  const [jobProvider, setJobProvider] = useState<CloudProvider>('meraki');
  // AWS / Azure / GCP accounts whose discovery request is in flight.
  const [cloudBusy, setCloudBusy] = useState<number[]>([]);
  const [allBusy, setAllBusy] = useState(false);
  const [allNote, setAllNote] = useState<{ text: string; failed: boolean } | null>(null);
  const [warningsFor, setWarningsFor] = useState<WarningsTarget | null>(null);

  const job = useMerakiBuildJob(jobId);
  const isJobRunning = jobId !== null && !job.isError && (!job.data || job.data.status === 'running');
  const isJobSettled = jobId !== null && !isJobRunning;

  const refreshMap = () => {
    qc.invalidateQueries({ queryKey: ['meraki'] });
    qc.invalidateQueries({ queryKey: ['topology'] });
    qc.invalidateQueries({ queryKey: ['mac-tracking'] });
  };

  // A settled job (finished, or its record expired) means new server state:
  // the topology graph now includes the new snapshot.
  useEffect(() => {
    if (!isJobSettled) return;
    refreshMap();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isJobSettled]);

  // Collections this dialog is not tracking by job (Collect All, another tab):
  // refresh the map when one of them stops.
  const collectingKeys = (sources.data?.sources ?? [])
    .filter((s) => s.collecting)
    .map((s) => s.key)
    .join(',');
  const prevCollectingRef = useRef('');
  useEffect(() => {
    const previous = prevCollectingRef.current;
    prevCollectingRef.current = collectingKeys;
    const still = new Set(collectingKeys.split(','));
    if (previous && previous.split(',').some((key) => !still.has(key))) refreshMap();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [collectingKeys]);

  const startOrgBuild = async (source: TopologySource): Promise<string> => {
    const started = await startBuild.mutateAsync(source.id as number);
    return started.job_id;
  };

  /** Resolves to an error message, or null when the discovery succeeded. */
  const runCloudDiscovery = async (source: TopologySource): Promise<string | null> => {
    const id = source.id as number;
    setCloudBusy((busy) => [...busy, id]);
    try {
      const result = await discoverCloud.mutateAsync(id);
      return result?.ok === false ? (result.message ?? 'Discovery failed') : null;
    } catch (err) {
      return errorText(err);
    } finally {
      setCloudBusy((busy) => busy.filter((item) => item !== id));
      refreshMap();
    }
  };

  const handleCollect = async (source: TopologySource) => {
    setAllNote(null);
    if (source.type === 'neighbors') {
      onDiscoverNeighbors();
      return;
    }
    if (isCloudAccountProvider(source.type)) {
      const failure = await runCloudDiscovery(source);
      if (failure) void alert({ message: `${source.name}: ${failure}`, variant: 'error' });
      return;
    }
    try {
      const started = await startOrgBuild(source);
      setJobProvider(source.type);
      setJobId(started);
    } catch (err) {
      void alert({ message: `Could not start the collection: ${errorText(err)}`, variant: 'error' });
    }
  };

  const canCollect = (source: TopologySource): boolean => {
    if (!source.can_collect || !source.enabled || source.collecting) return false;
    // AWS / Azure / GCP discovery belongs to Cloud Visibility, where it is an administrator action.
    return isCloudSource(source) ? isAdmin && !cloudBusy.includes(source.id as number) : canWrite;
  };

  const handleCollectAll = async () => {
    const targets = (sources.data?.sources ?? []).filter(canCollect);
    if (targets.length === 0) return;
    setAllBusy(true);
    setAllNote(null);
    setJobId(null);
    const failures: string[] = [];
    try {
      for (const source of targets.filter(isOrgSource)) {
        try {
          await startOrgBuild(source);
        } catch (err) {
          failures.push(`${source.name}: ${errorText(err)}`);
        }
      }
      if (targets.some((s) => s.type === 'neighbors')) onDiscoverNeighbors();
      const cloud = targets.filter(isCloudSource);
      const outcomes = await Promise.all(cloud.map(runCloudDiscovery));
      outcomes.forEach((failure, i) => {
        if (failure) failures.push(`${cloud[i].name}: ${failure}`);
      });
    } finally {
      setAllBusy(false);
      qc.invalidateQueries({ queryKey: ['meraki', 'sources'] });
    }
    setAllNote(
      failures.length
        ? { text: `Could not collect from ${failures.length} of ${targets.length}:\n${failures.join('\n')}`, failed: true }
        : {
            text: `Collection started for ${targets.length} source(s). The map updates as each one finishes.`,
            failed: false,
          },
    );
  };

  const handleSample = async (provider: CloudProvider | CloudAccountProvider) => {
    setJobId(null);
    setMenu(null);
    try {
      await buildSample.mutateAsync(provider);
    } catch (err) {
      void alert({ message: `Sample build failed: ${errorText(err)}`, variant: 'error' });
    }
  };

  const handleAdd = (provider: CloudProvider) => {
    setMenu(null);
    setAdding(provider);
  };

  const rows = sources.data?.sources ?? [];
  const orgById = new Map((orgs.data?.orgs ?? []).map((org) => [org.id, org]));
  const anyCollectable = rows.some(canCollect);

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Map Sources" size="large">
      <p className="text-muted" style={{ marginTop: 0, fontSize: '0.9rem' }}>
        Everything on the map comes from one of these sources. Inventory devices are scanned for their CDP
        and LLDP neighbors. Meraki organizations, Cato accounts, Cisco FMCs, Palo Alto Panoramas, Appgate SDP
        collectives, AWS accounts, Azure subscriptions and GCP projects are read from their APIs.
        Collect again whenever you want a fresh picture.
      </p>

      <div
        style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end', flexWrap: 'wrap', marginBottom: '0.75rem' }}
      >
        {canWrite && (
          <>
            <button
              type="button"
              className="btn btn-primary btn-sm"
              disabled={allBusy || !anyCollectable}
              title="Collect from every source you are allowed to collect from"
              onClick={handleCollectAll}
            >
              {allBusy ? 'Collecting…' : 'Collect All'}
            </button>
            <button
              type="button"
              className={`btn btn-sm ${menu === 'sample' ? 'btn-primary' : 'btn-secondary'}`}
              title="Preview a source with demo data - no API key needed"
              onClick={() => setMenu(menu === 'sample' ? null : 'sample')}
            >
              Load Sample
            </button>
          </>
        )}
        {isAdmin && (
          <button
            type="button"
            className={`btn btn-sm ${menu === 'add' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setMenu(menu === 'add' ? null : 'add')}
          >
            Add Source
          </button>
        )}
      </div>

      {menu === 'add' && (
        <div className="card" style={{ padding: '0.75rem 1rem', marginBottom: '0.75rem' }}>
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
            <strong>Add:</strong>
            <button type="button" className="btn btn-secondary btn-sm" onClick={() => handleAdd('meraki')}>
              Meraki Organization
            </button>
            <button type="button" className="btn btn-secondary btn-sm" onClick={() => handleAdd('cato')}>
              Cato Account
            </button>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              title="A Cisco Secure Firewall Management Center and the FTDs it manages"
              onClick={() => handleAdd('fmc')}
            >
              Cisco FMC
            </button>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              title="A Palo Alto Networks Panorama and the firewalls it manages"
              onClick={() => handleAdd('panorama')}
            >
              Palo Alto Panorama
            </button>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              title="An Appgate SDP collective: its Controllers, Gateways, sites, entitlements and connected users"
              onClick={() => handleAdd('appgate')}
            >
              Appgate SDP
            </button>
            <Link className="btn btn-secondary btn-sm" to={CLOUD_ACCOUNTS_PATH} onClick={onClose}>
              AWS Account
            </Link>
            <Link className="btn btn-secondary btn-sm" to={CLOUD_ACCOUNTS_PATH} onClick={onClose}>
              Azure Subscription
            </Link>
            <Link className="btn btn-secondary btn-sm" to={CLOUD_ACCOUNTS_PATH} onClick={onClose}>
              GCP Project
            </Link>
          </div>
          <div className="text-muted" style={{ fontSize: '0.85em', marginTop: '0.4rem' }}>
            AWS accounts, Azure subscriptions and GCP projects are added under Cloud Visibility, which also uses them
            for flow logs and policy. Inventory devices are added under Inventory.
          </div>
        </div>
      )}
      {menu === 'sample' && (
        <div className="card" style={{ padding: '0.75rem 1rem', marginBottom: '0.75rem' }}>
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
            <strong>Load demo data for:</strong>
            {(['meraki', 'cato', 'fmc', 'panorama', 'appgate', 'aws', 'azure', 'gcp'] as const).map((provider) => (
              <button
                key={provider}
                type="button"
                className="btn btn-secondary btn-sm"
                disabled={buildSample.isPending}
                onClick={() => handleSample(provider)}
              >
                {buildSample.isPending ? 'Building…' : providerLabel(provider)}
              </button>
            ))}
          </div>
          <div className="text-muted" style={{ fontSize: '0.85em', marginTop: '0.4rem' }}>
            Each adds a demo source to the map. Delete it from this list when you are done (the AWS, Azure and GCP
            ones under Cloud Visibility).
          </div>
        </div>
      )}

      {sources.isPending && <div className="loading">Loading sources…</div>}
      {sources.error && (
        <div className="error">
          <strong>Failed to load sources:</strong> {sources.error.message}
        </div>
      )}
      {sources.data && (
        <table className="data-table">
          <thead>
            <tr>
              <th>Source</th>
              <th>Type</th>
              <th>Last Collection</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((source) => (
              <SourceRow
                key={source.key}
                source={source}
                org={source.id != null && !isCloudSource(source) ? orgById.get(source.id) : undefined}
                isAdmin={isAdmin}
                canWrite={canWrite}
                canCollect={
                  canCollect(source) &&
                  !allBusy &&
                  // One tracked organization collection at a time, as its progress is shown below.
                  !(isOrgSource(source) && (isJobRunning || startBuild.isPending))
                }
                isBusy={source.collecting || (isCloudSource(source) && cloudBusy.includes(source.id as number))}
                isSampleBusy={buildSample.isPending}
                onCollect={() => handleCollect(source)}
                onReloadSample={() => handleSample(source.type as CloudProvider | CloudAccountProvider)}
                onEdit={setEditing}
                onNavigate={onClose}
                onShowWarnings={setWarningsFor}
              />
            ))}
          </tbody>
        </table>
      )}

      {allNote && (
        <div
          className={allNote.failed ? 'error' : 'card'}
          style={{ marginTop: '1rem', padding: '0.75rem 1rem', whiteSpace: 'pre-line' }}
        >
          {allNote.text}
        </div>
      )}
      {isJobRunning && <BuildProgress job={job.data} provider={jobProvider} />}
      {isJobSettled && (
        <BuildOutcome job={job.data} onDismiss={() => setJobId(null)} onShowWarnings={setWarningsFor} />
      )}

      <h4 style={{ margin: '1.25rem 0 0.5rem' }}>Collection history (Meraki, Cato, Cisco FMC, Palo Alto Panorama and Appgate SDP)</h4>
      {snapshots.isPending && <div className="loading">Loading history…</div>}
      {snapshots.error && (
        <div className="error">
          <strong>Failed to load history:</strong> {snapshots.error.message}
        </div>
      )}
      {snapshots.data && (
        <SnapshotTable snapshots={snapshots.data.snapshots} canWrite={canWrite} onShowWarnings={setWarningsFor} />
      )}

      {warningsFor && <WarningsModal target={warningsFor} onClose={() => setWarningsFor(null)} />}

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
      {(adding ?? editing?.provider) === 'fmc' && (
        <FmcFormModal
          existing={editing}
          defaultOptions={orgs.data?.fmc_default_options ?? FALLBACK_FMC_OPTIONS}
          onClose={() => {
            setAdding(null);
            setEditing(null);
          }}
        />
      )}
      {(adding ?? editing?.provider) === 'panorama' && (
        <PanoramaFormModal
          existing={editing}
          defaultOptions={orgs.data?.panorama_default_options ?? FALLBACK_PANORAMA_OPTIONS}
          onClose={() => {
            setAdding(null);
            setEditing(null);
          }}
        />
      )}
      {(adding ?? editing?.provider) === 'appgate' && (
        <AppgateFormModal
          existing={editing}
          defaultOptions={orgs.data?.appgate_default_options ?? FALLBACK_APPGATE_OPTIONS}
          onClose={() => {
            setAdding(null);
            setEditing(null);
          }}
        />
      )}
    </Modal>
  );
}

interface SourceRowProps {
  source: TopologySource;
  /** The organization behind a Meraki or Cato source, once loaded. */
  org: MerakiOrg | undefined;
  isAdmin: boolean;
  canWrite: boolean;
  canCollect: boolean;
  isBusy: boolean;
  isSampleBusy: boolean;
  onCollect: () => void;
  onReloadSample: () => void;
  onEdit: (org: MerakiOrg) => void;
  /** Called when a link leaves the Topology page. */
  onNavigate: () => void;
  onShowWarnings: ShowWarnings;
}

function collectTitle(source: TopologySource, isAdmin: boolean): string {
  if (source.type === 'neighbors') {
    return source.can_collect
      ? 'Scan inventory devices over SNMP for their CDP and LLDP neighbors (the group selected on the map, or all groups)'
      : 'No devices in inventory';
  }
  if (isCloudSource(source)) {
    const scopeName = providerScopeName(source.type);
    if (!source.enabled) return `This ${scopeName} is disabled in Cloud Visibility`;
    return isAdmin ? `Discover this ${scopeName} and update the map` : `${providerLabel(source.type)} discovery needs an administrator`;
  }
  if (source.can_collect) return `Collect from ${providerLabel(source.type)} and update the map`;
  if (source.type === 'fmc' || source.type === 'appgate') return 'No password stored';
  return source.type === 'panorama' ? 'No password or API key stored' : 'No API key stored';
}

function SourceRow({
  source,
  org,
  isAdmin,
  canWrite,
  canCollect,
  isBusy,
  isSampleBusy,
  onCollect,
  onReloadSample,
  onEdit,
  onNavigate,
  onShowWarnings,
}: SourceRowProps) {
  const { confirm, alert } = useDialogs();
  const validate = useValidateMerakiOrg();
  const remove = useDeleteMerakiOrg();
  const isOrg = isOrgSource(source);

  const handleValidate = async () => {
    try {
      const result = await validate.mutateAsync(source.id as number);
      const visible = result.organizations.map((o) => `${o.name} (ID ${o.id})`).join('\n');
      void alert({
        message:
          visible && source.type === 'meraki'
            ? `${result.message}\n\nVisible organizations:\n${visible}`
            : visible && source.type === 'fmc'
              ? `${result.message}\n\nDomains the account can see:\n${visible}`
              : visible && source.type === 'panorama'
                ? `${result.message}\n\nDevice groups the account can see:\n${visible}`
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
        `Delete "${source.name}"?\n\nIts devices leave the topology map, and its stored API key and collection history are deleted.`,
      ))
    ) {
      return;
    }
    try {
      await remove.mutateAsync(source.id as number);
    } catch (err) {
      void alert({ message: `Delete failed: ${errorText(err)}`, variant: 'error' });
    }
  };

  return (
    <tr>
      <td>
        {source.name}
        {source.demo && (
          <>
            {' '}
            <span className="badge">demo</span>
          </>
        )}
        {!source.enabled && (
          <>
            {' '}
            <span className="badge badge-warning" title="Disabled in Cloud Visibility: not on the map">
              disabled
            </span>
          </>
        )}
      </td>
      <td>
        <span className="badge">{sourceTypeLabel(source.type)}</span>
      </td>
      <td>
        {isBusy ? (
          <span className="badge badge-info">Collecting…</span>
        ) : (
          <>
            <span className={buildStatusBadge(source.status)}>{source.status || 'never'}</span>{' '}
            <span className="text-muted">{source.last_collected_at ? formatWhen(source.last_collected_at) : ''}</span>
            {source.warning_count > 0 && (
              <>
                {' '}
                <WarningsBadge
                  text={`${source.warning_count} warning(s)`}
                  onClick={
                    source.snapshot_id != null
                      ? () => onShowWarnings({ snapshotId: source.snapshot_id as number, name: source.name })
                      : undefined
                  }
                />
              </>
            )}
            {(source.detail || source.message) && (
              <div className="text-muted" style={{ fontSize: '0.85em' }}>
                {[source.detail, source.message].filter(Boolean).join(' · ')}
              </div>
            )}
          </>
        )}
      </td>
      <td>
        <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap' }}>
          {source.demo && canWrite ? (
            <button
              type="button"
              className="btn btn-sm btn-primary"
              disabled={isSampleBusy}
              title="Load the demo data again"
              onClick={onReloadSample}
            >
              Reload Sample
            </button>
          ) : (
            (isCloudSource(source) ? isAdmin : canWrite) && (
              <button
                type="button"
                className="btn btn-sm btn-primary"
                disabled={!canCollect}
                title={collectTitle(source, isAdmin)}
                onClick={onCollect}
              >
                Collect Now
              </button>
            )
          )}
          {isOrg && isAdmin && (
            <>
              <button
                type="button"
                className="btn btn-sm btn-secondary"
                disabled={!source.can_collect || validate.isPending}
                onClick={handleValidate}
              >
                {validate.isPending ? '…' : LOGIN_SOURCE_TYPES.has(source.type) ? 'Test Login' : 'Test Key'}
              </button>
              <button
                type="button"
                className="btn btn-sm btn-secondary"
                disabled={!org}
                onClick={() => org && onEdit(org)}
              >
                Edit
              </button>
              <button
                type="button"
                className="btn btn-sm btn-danger"
                disabled={remove.isPending || source.collecting}
                onClick={handleDelete}
              >
                Del
              </button>
            </>
          )}
          {isCloudSource(source) && (
            <Link
              className="btn btn-sm btn-secondary"
              to={CLOUD_ACCOUNTS_PATH}
              title={`${providerLabel(source.type)} accounts are edited, validated and deleted under Cloud Visibility`}
              onClick={onNavigate}
            >
              Manage
            </Link>
          )}
          {source.type === 'neighbors' && (
            <Link
              className="btn btn-sm btn-secondary"
              to="/inventory"
              title="Devices and their SNMP credentials are managed under Inventory"
              onClick={onNavigate}
            >
              Manage
            </Link>
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
          : provider === 'fmc'
            ? 'An FMC takes several requests per device (interfaces, routing, NAT, policies), sent slowly to stay inside the FMC limit of 120 requests per minute.'
            : provider === 'panorama'
              ? 'A Panorama takes a few requests per device group and template, plus a few per firewall when device state is collected.'
              : provider === 'appgate'
                ? 'An Appgate collective takes one query per connected user for the access details; large user counts take a while.'
            : 'Large organizations take several minutes: Meraki limits the API to 10 requests per second.'}{' '}
        You can close this dialog; the map updates when collection finishes.
      </div>
    </div>
  );
}

function BuildOutcome({
  job,
  onDismiss,
  onShowWarnings,
}: {
  job: MerakiBuildJob | undefined;
  onDismiss: () => void;
  onShowWarnings: ShowWarnings;
}) {
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
                <>
                  {' '}
                  <WarningsBadge
                    text={`${result.warning_count} collection warning(s)`}
                    onClick={() => onShowWarnings({ snapshotId: result.snapshot_id, name: 'Latest collection' })}
                  />
                </>
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

function SnapshotTable({
  snapshots,
  canWrite,
  onShowWarnings,
}: {
  snapshots: MerakiSnapshot[];
  canWrite: boolean;
  onShowWarnings: ShowWarnings;
}) {
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
                <WarningsBadge
                  text={s.warning_count}
                  onClick={() =>
                    onShowWarnings({
                      snapshotId: s.id,
                      name: `${s.org_name ?? 'Collection'} - ${formatWhen(s.created_at)}`,
                    })
                  }
                />
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

/** The API calls one collection could not make, so a partial map can be explained. */
function WarningsModal({ target, onClose }: { target: WarningsTarget; onClose: () => void }) {
  const warnings = useSnapshotWarnings(target.snapshotId);
  const rows = warnings.data?.warnings ?? [];
  return (
    <Modal isOpen onClose={onClose} title={`Collection warnings - ${target.name}`} size="large">
      <p className="text-muted" style={{ marginTop: 0, fontSize: '0.9rem' }}>
        These API calls failed or were refused during the collection. The rest of the map was built; what these calls
        would have added (users, subnets, WAN links...) is missing from it.
      </p>
      {warnings.isPending && <div className="loading">Loading warnings…</div>}
      {warnings.error && (
        <div className="error">
          <strong>Failed to load warnings:</strong> {warnings.error.message}
        </div>
      )}
      {warnings.data && rows.length === 0 && <p className="text-muted">No warnings recorded.</p>}
      {rows.length > 0 && (
        <table className="data-table">
          <thead>
            <tr>
              <th>Scope</th>
              <th>Request</th>
              <th>HTTP</th>
              <th>Message</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((w, i) => (
              <tr key={i}>
                <td>{w.scope}</td>
                <td style={{ wordBreak: 'break-all' }}>
                  <code>{w.path}</code>
                </td>
                <td>{w.status ?? ''}</td>
                <td style={{ whiteSpace: 'pre-wrap' }}>{w.message}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Modal>
  );
}
