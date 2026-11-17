import { useState } from 'react';
import { Link } from 'react-router';

import { useAuthStatus } from '@/api/auth';
import {
  type HardwareNotice,
  type SupportContract,
  lifecycleExportUrl,
  useDeleteContract,
  useDeleteNotice,
  useFleetLifecycle,
  useHardwareNotices,
  useRunLifecycleCheck,
  useSupportContracts,
} from '@/api/lifecycle';
import { BusyButton } from '@/components/BusyButton';
import { CardHeader, CatalogueBody, Dash, RowActions } from '@/components/CatalogueParts';
import { DataTable } from '@/components/DataTable';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { PageHelp } from '@/components/PageHelp';
import { QueryError } from '@/components/QueryError';
import { TabBar } from '@/components/TabBar';
import { useConfirmDelete } from '@/components/useConfirmDelete';
import { formatBackendDateTime } from '@/lib/datetime';
import {
  COVERAGE,
  type CoverageState,
  formatCost,
  formatDateWithDays,
  type LifecycleFilter,
  type LifecycleStage,
  noticeTarget,
  STAGES,
} from '@/lib/lifecycle';
import { canWriteFeature } from '@/lib/tabGating';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { ContractModal, LifecycleSettingsModal, NoticeModal } from './LifecycleModals';
import { ContractStateBadge, CoverageBadge, StageBadge } from './LifecycleParts';

const SECTIONS = [
  { key: 'devices', label: 'Devices' },
  { key: 'notices', label: 'End-of-life notices' },
  { key: 'contracts', label: 'Support contracts' },
] as const;
type Section = (typeof SECTIONS)[number]['key'];

const RIGHT = { textAlign: 'right' } as const;

/** Whether the user may change lifecycle records (admin, or `lifecycle.write`). */
function useCanWriteLifecycle(): boolean {
  return canWriteFeature('lifecycle', useAuthStatus().data);
}

/**
 * The Software page's Lifecycle tab: the fleet's hardware lifecycle (end of
 * sale and support per device, contract coverage), end-of-life notices and
 * support contracts.
 */
export function LifecycleTab() {
  const [section, setSection] = useState<Section>('devices');
  return (
    <div>
      <PageHelp
        guide="Hardware-Lifecycle"
        pageKey="software.lifecycle"
        title="Hardware Lifecycle"
        text="End-of-life notices on device types and part numbers, the support contracts that cover each device, and where every device stands: end of sale, end of software maintenance and security fixes, last date of support, and whether a contract covers it. Plexus checks every six hours and raises a monitoring alert when a device passes or nears its last date of support, or its contract coverage is ending or has ended."
      />
      <TabBar size="sm" tabs={SECTIONS} active={section} onChange={setSection} aria-label="Lifecycle sections" />
      {section === 'devices' && <DevicesSection />}
      {section === 'notices' && <NoticesSection />}
      {section === 'contracts' && <ContractsSection />}
    </div>
  );
}

// ── Devices ────────────────────────────────────────────────────────────────

function DevicesSection() {
  const canWrite = useCanWriteLifecycle();
  const { alert } = useDialogs();
  const [stage, setStage] = useState<LifecycleStage | ''>('');
  const [coverage, setCoverage] = useState<CoverageState | ''>('');
  const [search, setSearch] = useState('');
  const [settingsOpen, setSettingsOpen] = useState(false);
  const filter: LifecycleFilter = { stage: stage || undefined, coverage: coverage || undefined, q: search.trim() || undefined };
  const q = useFleetLifecycle(filter);
  const check = useRunLifecycleCheck();
  const summary = q.data?.summary;
  const settings = q.data?.settings;
  const devices = q.data?.devices ?? [];
  const filtered = Boolean(stage || coverage || search.trim());

  const runCheck = async () => {
    try {
      const result = await check.mutateAsync();
      void alert({
        title: 'Lifecycle check done',
        message: `${result.conditions} condition(s) need an alert; ${result.raised} new alert(s) raised, ${result.cleared} cleared.`,
      });
    } catch (err) {
      void alert({ message: (err as Error).message, variant: 'error' });
    }
  };

  const cards = [
    { label: 'Devices', value: summary?.devices ?? 0 },
    { label: 'With a notice', value: summary?.with_notice ?? 0 },
    {
      label: 'Past end of sale',
      value:
        (summary?.by_stage.end_of_sale ?? 0) +
        (summary?.by_stage.end_of_sw_maintenance ?? 0) +
        (summary?.by_stage.end_of_security_fixes ?? 0),
    },
    { label: 'Past end of support', value: summary?.past_end_of_support ?? 0, danger: true },
    { label: 'Contracts expiring', value: summary?.by_coverage.expiring ?? 0, warn: true },
    { label: 'Contracts expired', value: summary?.by_coverage.expired ?? 0, danger: true },
  ];

  return (
    <div className="stack">
      <div className="toolbar">
        <input
          type="search"
          aria-label="Search devices"
          className="form-input form-input-sm"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search name, IP, device type"
          style={{ flex: '1 1 220px', maxWidth: 320 }}
        />
        <select
          aria-label="Stage"
          className="form-select form-select-sm"
          value={stage}
          onChange={(e) => setStage(e.target.value as LifecycleStage | '')}
        >
          <option value="">All stages</option>
          {STAGES.map((s) => (
            <option key={s.value} value={s.value}>
              {s.label}
            </option>
          ))}
        </select>
        <select
          aria-label="Contract coverage"
          className="form-select form-select-sm"
          value={coverage}
          onChange={(e) => setCoverage(e.target.value as CoverageState | '')}
        >
          <option value="">All coverage</option>
          {COVERAGE.map((c) => (
            <option key={c.value} value={c.value}>
              {c.label}
            </option>
          ))}
        </select>
        <span className="toolbar-spacer" />
        <a className="btn btn-sm btn-secondary" href={lifecycleExportUrl(filter)} download>
          Export CSV
        </a>
        {canWrite && (
          <BusyButton className="btn btn-sm btn-secondary" busy={check.isPending} busyLabel="Checking…" onClick={() => void runCheck()}>
            Run alert check
          </BusyButton>
        )}
        {canWrite && settings && (
          <button type="button" className="btn btn-sm btn-secondary" onClick={() => setSettingsOpen(true)}>
            Alert settings
          </button>
        )}
        {settings && (
          <div className="text-muted" style={{ flexBasis: '100%', fontSize: '0.85em' }}>
            Alerts {settings.alerts_enabled ? 'on' : 'off'} · contracts warned {settings.contract_warn_days} days ahead,
            support {settings.support_warn_days} days ahead · last check{' '}
            {formatBackendDateTime(settings.last_check_at, 'never')}
          </div>
        )}
      </div>

      {q.isError && !q.data ? (
        <QueryError what="hardware lifecycle" query={q} />
      ) : (
        <>
          <div
            className="stats-grid"
            style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 'var(--space-4)' }}
          >
            {cards.map((card) => (
              <div key={card.label} className="stat-card">
                <div
                  className="stat-value"
                  style={
                    card.value > 0 && card.danger
                      ? { color: 'var(--danger)' }
                      : card.value > 0 && card.warn
                        ? { color: 'var(--warning)' }
                        : undefined
                  }
                >
                  {card.value.toLocaleString()}
                </div>
                <div className="stat-label">{card.label}</div>
              </div>
            ))}
          </div>
          <div className="card">
            <CardHeader
              title="Devices"
              sub={q.data && `${devices.length.toLocaleString()} device${devices.length === 1 ? '' : 's'}${filtered ? ' matching the filter' : ''}`}
            />
            <CatalogueBody
              query={{ ...q, data: q.data ? devices : undefined }}
              what="devices"
              rows={devices}
              empty={
                <EmptyState
                  compact
                  message={filtered ? 'No device matches the filter.' : 'No devices in the inventory yet.'}
                />
              }
            >
              <DataTable compact aria-label="Device lifecycle">
                <thead>
                  <tr>
                    <th>Device</th>
                    <th>Device type</th>
                    <th>Stage</th>
                    <th>End of sale</th>
                    <th>Last date of support</th>
                    <th>Next milestone</th>
                    <th>Coverage</th>
                  </tr>
                </thead>
                <tbody>
                  {devices.map((d) => (
                    <tr key={d.host_id}>
                      <td>
                        <Link to={`/devices/${d.host_id}`} style={{ fontWeight: 600 }}>
                          {d.hostname || d.ip_address}
                        </Link>
                        <div className="text-muted" style={{ fontSize: '0.85em' }}>
                          {d.ip_address}
                        </div>
                      </td>
                      <td>{d.device_type_model ? `${d.manufacturer_name ?? ''} ${d.device_type_model}`.trim() : <Dash />}</td>
                      <td>
                        <StageBadge stage={d.stage} />
                      </td>
                      <td>{formatDateWithDays(d.end_of_sale, d.days_to_end_of_sale)}</td>
                      <td>{formatDateWithDays(d.end_of_support, d.days_to_end_of_support)}</td>
                      <td>{d.next ? `${d.next.label}: ${formatDateWithDays(d.next.date, d.next.days)}` : <Dash />}</td>
                      <td>
                        <CoverageBadge coverage={d.coverage} />
                        {d.coverage_end && (
                          <div className="text-muted" style={{ fontSize: '0.85em' }}>
                            until {formatDateWithDays(d.coverage_end, d.coverage_days)}
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </DataTable>
            </CatalogueBody>
          </div>
        </>
      )}
      {settingsOpen && settings && <LifecycleSettingsModal settings={settings} onClose={() => setSettingsOpen(false)} />}
    </div>
  );
}

// ── Notices ────────────────────────────────────────────────────────────────

function NoticesSection() {
  const canWrite = useCanWriteLifecycle();
  const q = useHardwareNotices();
  const remove = useDeleteNotice();
  const confirmDelete = useConfirmDelete();
  const deleting = usePendingKeys<number>();
  const [editing, setEditing] = useState<HardwareNotice | 'new' | null>(null);
  const rows = q.data ?? [];

  const addButton = canWrite && (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing('new')}>
      Add notice
    </button>
  );

  return (
    <div className="card">
      <CardHeader
        title="End-of-life notices"
        sub={q.data && `${rows.length.toLocaleString()} notice${rows.length === 1 ? '' : 's'}`}
        actions={rows.length > 0 && addButton}
      />
      <CatalogueBody
        query={q}
        what="notices"
        rows={rows}
        empty={
          <EmptyState
            compact
            message="No end-of-life notices yet."
            description="Add the vendor's end-of-sale and end-of-support dates for a device type or part number; every device of that model then shows them."
            action={addButton || undefined}
          />
        }
      >
        <DataTable compact aria-label="End-of-life notices">
          <thead>
            <tr>
              <th>Hardware</th>
              <th style={RIGHT}>Devices</th>
              <th>Stage today</th>
              <th>End of sale</th>
              <th>End of SW maintenance</th>
              <th>End of security fixes</th>
              <th>Last date of support</th>
              {canWrite && <th style={RIGHT}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {rows.map((n) => (
              <tr key={n.id}>
                <td>
                  <span style={{ fontWeight: 600 }}>{noticeTarget(n)}</span>
                  {n.documentation_url && (
                    <div style={{ fontSize: '0.85em' }}>
                      <a href={n.documentation_url} target="_blank" rel="noopener noreferrer">
                        Vendor notice
                      </a>
                    </div>
                  )}
                </td>
                <td style={RIGHT}>{n.host_count.toLocaleString()}</td>
                <td>
                  <StageBadge stage={n.stage} />
                </td>
                <td>{n.end_of_sale || <Dash />}</td>
                <td>{n.end_of_sw_maintenance || <Dash />}</td>
                <td>{n.end_of_security_fixes || <Dash />}</td>
                <td>{n.end_of_support || <Dash />}</td>
                {canWrite && (
                  <td style={RIGHT}>
                    <RowActions
                      label={`notice for ${noticeTarget(n)}`}
                      onEdit={() => setEditing(n)}
                      onDelete={() =>
                        void deleting.run(n.id, () =>
                          confirmDelete('notice', noticeTarget(n), () => remove.mutateAsync(n.id)),
                        )
                      }
                      deleting={deleting.isPending(n.id)}
                    />
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </DataTable>
      </CatalogueBody>
      {editing && <NoticeModal notice={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
    </div>
  );
}

// ── Contracts ──────────────────────────────────────────────────────────────

function ContractsSection() {
  const canWrite = useCanWriteLifecycle();
  const q = useSupportContracts();
  const remove = useDeleteContract();
  const confirmDelete = useConfirmDelete();
  const deleting = usePendingKeys<number>();
  const [editing, setEditing] = useState<SupportContract | 'new' | null>(null);
  const rows = q.data ?? [];

  const addButton = canWrite && (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing('new')}>
      Add contract
    </button>
  );

  return (
    <div className="card">
      <CardHeader
        title="Support contracts"
        sub={q.data && `${rows.length.toLocaleString()} contract${rows.length === 1 ? '' : 's'}`}
        actions={rows.length > 0 && addButton}
      />
      <CatalogueBody
        query={q}
        what="contracts"
        rows={rows}
        empty={
          <EmptyState
            compact
            message="No support contracts yet."
            description="Add a contract with its end date and the devices it covers; Plexus warns before it runs out."
            action={addButton || undefined}
          />
        }
      >
        <DataTable compact aria-label="Support contracts">
          <thead>
            <tr>
              <th>Provider</th>
              <th>Contract ID</th>
              <th>State</th>
              <th>Start</th>
              <th>End</th>
              <th>Support level</th>
              <th style={RIGHT}>Cost</th>
              <th style={RIGHT}>Devices</th>
              {canWrite && <th style={RIGHT}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {rows.map((c) => (
              <tr key={c.id}>
                <td style={{ fontWeight: 600 }}>{c.provider}</td>
                <td>{c.contract_id}</td>
                <td>
                  <ContractStateBadge state={c.state} />
                </td>
                <td>{c.start_date || <Dash />}</td>
                <td>{c.end_date || <span className="text-muted">Open</span>}</td>
                <td>{c.support_level || <Dash />}</td>
                <td style={RIGHT}>{formatCost(c.cost, c.currency)}</td>
                <td style={RIGHT} title={c.hosts.map((h) => h.hostname).join(', ')}>
                  {c.host_count.toLocaleString()}
                </td>
                {canWrite && (
                  <td style={RIGHT}>
                    <RowActions
                      label={`contract ${c.contract_id}`}
                      onEdit={() => setEditing(c)}
                      onDelete={() =>
                        void deleting.run(c.id, () =>
                          confirmDelete('contract', `${c.provider} ${c.contract_id}`, () => remove.mutateAsync(c.id)),
                        )
                      }
                      deleting={deleting.isPending(c.id)}
                    />
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </DataTable>
      </CatalogueBody>
      {editing && <ContractModal contract={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
    </div>
  );
}
