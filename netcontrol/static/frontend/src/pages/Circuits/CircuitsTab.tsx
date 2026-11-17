import { useDeferredValue, useState } from 'react';
import { Link } from 'react-router';

import {
  type Circuit,
  type CircuitStatus,
  useCircuit,
  useCircuitProviders,
  useCircuits,
  useCircuitTypes,
  useDeleteCircuit,
} from '@/api/circuits';
import { CardHeader, CatalogueBody, Dash, RowActions } from '@/components/CatalogueParts';
import { ChangelogPanel } from '@/components/ChangelogPanel';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import {
  CIRCUIT_STATUSES,
  type CircuitFilter,
  formatBps,
  formatKbps,
  TERM_SIDES,
  terminationOf,
  terminationSummary,
} from '@/lib/circuits';
import { clickableProps } from '@/lib/clickable';
import { usePendingKeys } from '@/lib/usePendingKeys';
import { DETAIL_STACK_STYLE } from '@/lib/wideDetail';
import { DetailSection, SplitLayout } from '@/pages/Ipam/NetworkObjectParts';

import { CircuitModal } from './CircuitModal';
import { useCanWriteCircuits, useConfirmDelete } from './hooks';
import { CircuitStatusBadge, DetailRow } from './parts';

const RIGHT = { textAlign: 'right' } as const;

/** The circuits, filtered, and the selected one's terminations, utilisation and change log. */
export function CircuitsTab() {
  const canWrite = useCanWriteCircuits();
  const [search, setSearch] = useState('');
  const [providerId, setProviderId] = useState('');
  const [typeId, setTypeId] = useState('');
  const [status, setStatus] = useState('');
  const q = useDeferredValue(search.trim());
  const filter: CircuitFilter = {
    q: q || undefined,
    provider_id: providerId ? Number(providerId) : undefined,
    circuit_type_id: typeId ? Number(typeId) : undefined,
    status: (status || undefined) as CircuitStatus | undefined,
  };
  const filtered = Boolean(filter.q || filter.provider_id || filter.circuit_type_id || filter.status);
  const circuits = useCircuits(filter);
  const providers = useCircuitProviders();
  const types = useCircuitTypes();
  const remove = useDeleteCircuit();
  const confirmDelete = useConfirmDelete();
  const deleting = usePendingKeys<number>();
  const [editing, setEditing] = useState<Circuit | 'new' | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const rows = circuits.data ?? [];
  const ready = (providers.data?.length ?? 0) > 0 && (types.data?.length ?? 0) > 0;

  const addButton = canWrite && (
    <button
      type="button"
      className="btn btn-sm btn-primary"
      disabled={!ready}
      title={ready ? undefined : 'Add a provider and a circuit type first'}
      onClick={() => setEditing('new')}
    >
      Add circuit
    </button>
  );

  const list = (
    <>
      <CardHeader
        title="Circuits"
        sub={circuits.data && `${rows.length.toLocaleString()} circuit${rows.length === 1 ? '' : 's'}${filtered ? ' match' : ''}`}
        actions={addButton}
      />
      <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap', marginBottom: '0.75rem' }}>
        <input
          className="form-input"
          style={{ flex: '1 1 12rem', maxWidth: '20rem' }}
          type="search"
          aria-label="Search circuits"
          placeholder="Search circuit ID or description"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select className="form-select" style={{ width: 'auto' }} aria-label="Provider" value={providerId} onChange={(e) => setProviderId(e.target.value)}>
          <option value="">All providers</option>
          {(providers.data ?? []).map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
        <select className="form-select" style={{ width: 'auto' }} aria-label="Circuit type" value={typeId} onChange={(e) => setTypeId(e.target.value)}>
          <option value="">All types</option>
          {(types.data ?? []).map((t) => (
            <option key={t.id} value={t.id}>
              {t.name}
            </option>
          ))}
        </select>
        <select className="form-select" style={{ width: 'auto' }} aria-label="Status" value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">All statuses</option>
          {CIRCUIT_STATUSES.map((s) => (
            <option key={s.value} value={s.value}>
              {s.label}
            </option>
          ))}
        </select>
      </div>
      <CatalogueBody
        query={circuits}
        what="circuits"
        rows={rows}
        empty={
          filtered ? (
            <EmptyState
              compact
              message="No circuits match."
              action={
                <button
                  type="button"
                  className="btn btn-sm btn-secondary"
                  onClick={() => {
                    setSearch('');
                    setProviderId('');
                    setTypeId('');
                    setStatus('');
                  }}
                >
                  Clear filters
                </button>
              }
            />
          ) : (
            <EmptyState
              compact
              message="No circuits yet."
              description={
                ready
                  ? 'Record the carrier circuits you buy, where each end lands, and the device port it plugs into.'
                  : 'Add a provider and a circuit type first, on their tabs.'
              }
              action={addButton || undefined}
            />
          )
        }
      >
        <DataTable compact aria-label="Circuits">
          <thead>
            <tr>
              <th>Circuit ID</th>
              <th>Provider</th>
              <th>Type</th>
              <th>Status</th>
              <th style={RIGHT}>Commit</th>
              <th>A side</th>
              <th>Z side</th>
              {canWrite && <th style={RIGHT}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {rows.map((c) => (
              <tr
                key={c.id}
                className={`row-clickable${c.id === selectedId ? ' row-selected' : ''}`}
                aria-current={c.id === selectedId ? 'true' : undefined}
                title="Show the circuit's details"
                {...clickableProps(() => setSelectedId(c.id), { role: null })}
              >
                <td style={{ fontWeight: 600 }}>{c.cid}</td>
                <td>{c.provider_name}</td>
                <td>{c.circuit_type_name}</td>
                <td>
                  <CircuitStatusBadge status={c.status} />
                </td>
                <td style={RIGHT}>{formatKbps(c.commit_rate_kbps)}</td>
                <td>{terminationSummary(terminationOf(c, 'A'))}</td>
                <td>{terminationSummary(terminationOf(c, 'Z'))}</td>
                {canWrite && (
                  <td style={RIGHT} onClick={(e) => e.stopPropagation()}>
                    <RowActions
                      label={`circuit ${c.cid}`}
                      onEdit={() => setEditing(c)}
                      onDelete={() =>
                        void deleting.run(c.id, async () => {
                          if (await confirmDelete('circuit', c.cid, () => remove.mutateAsync(c.id))) {
                            if (selectedId === c.id) setSelectedId(null);
                          }
                        })
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
      {editing && <CircuitModal circuit={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
    </>
  );

  return <SplitLayout list={list} detail={<CircuitDetailPanel id={selectedId} />} />;
}

export function CircuitDetailPanel({ id }: { id: number | null }) {
  const q = useCircuit(id);
  if (id === null) {
    return (
      <>
        <h3 style={{ margin: '0 0 0.75rem' }}>Circuit details</h3>
        <p className="text-muted" style={{ margin: 0 }}>
          Select a circuit to see its terminations, utilisation and change log.
        </p>
      </>
    );
  }
  if (q.isError && !q.data) return <QueryError what="circuit details" query={q} />;
  if (q.isPending) return <LoadingState text="Loading circuit details…" />;
  const c = q.data;
  const utilisation = c.utilisation ?? [];
  return (
    <div style={DETAIL_STACK_STYLE}>
      <div>
        <h3 style={{ margin: 0 }}>{c.cid}</h3>
        <div className="text-muted" style={{ fontSize: '0.9em' }}>
          {c.provider_name} · {c.circuit_type_name}
          {c.description ? ` · ${c.description}` : ''}
        </div>
      </div>
      <div style={{ display: 'grid', gap: '0.3rem' }}>
        <DetailRow label="Status">
          <CircuitStatusBadge status={c.status} />
        </DetailRow>
        <DetailRow label="Commit rate">{formatKbps(c.commit_rate_kbps)}</DetailRow>
        <DetailRow label="Tenant">{c.tenant_name ?? <Dash />}</DetailRow>
        <DetailRow label="Installed">{c.install_date || <Dash />}</DetailRow>
        <DetailRow label="Terminates">{c.termination_date || <Dash />}</DetailRow>
        <DetailRow label="Billing">
          {c.billing_circuit_name ? `${c.billing_circuit_name}${c.billing_customer ? ` (${c.billing_customer})` : ''}` : <Dash />}
        </DetailRow>
        {c.comments && <DetailRow label="Comments">{c.comments}</DetailRow>}
      </div>
      {TERM_SIDES.map((side) => {
        const t = terminationOf(c, side);
        return (
          <section key={side} aria-label={`${side} termination`}>
            <div style={{ fontWeight: 600, marginBottom: '0.45rem' }}>{side} termination</div>
            {t ? (
              <div style={{ display: 'grid', gap: '0.3rem' }}>
                <DetailRow label={t.site_id ? 'Site' : 'Provider network'}>{t.site_name ?? t.provider_network_name}</DetailRow>
                <DetailRow label="Device">
                  {t.host_id ? (
                    <Link to={`/devices/${t.host_id}`}>
                      {t.hostname}
                      {t.interface_name ? ` ${t.interface_name}` : ''}
                    </Link>
                  ) : (
                    <Dash />
                  )}
                </DetailRow>
                <DetailRow label="Port / upstream">
                  {formatKbps(t.port_speed_kbps)} / {formatKbps(t.upstream_speed_kbps)}
                </DetailRow>
                <DetailRow label="Cross-connect">{t.xconnect_id || <Dash />}</DetailRow>
                <DetailRow label="Patch panel">{t.pp_info || <Dash />}</DetailRow>
                {t.description && <DetailRow label="Description">{t.description}</DetailRow>}
              </div>
            ) : (
              <EmptyState compact message={`No ${side} termination.`} />
            )}
          </section>
        );
      })}
      <DetailSection
        title="Utilisation"
        count={utilisation.length}
        empty="No utilisation: it needs a commit rate and a termination on a device port Plexus polls."
      >
        <UtilisationTable rows={utilisation} />
      </DetailSection>
      <ChangelogPanel objectType="circuit" objectId={c.id} pageSize={10} />
    </div>
  );
}

/** The latest in / out rate of each termination port, against the commit rate. */
export function UtilisationTable({ rows }: { rows: NonNullable<Circuit['utilisation']> }) {
  return (
    <DataTable compact aria-label="Circuit utilisation">
      <thead>
        <tr>
          <th>Side</th>
          <th>Interface</th>
          <th style={RIGHT}>In</th>
          <th style={RIGHT}>Out</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((u) => (
          <tr key={u.term_side}>
            <td>{u.term_side}</td>
            <td>{u.interface_name}</td>
            <td style={RIGHT}>
              {formatBps(u.in_bps)} ({u.in_pct_of_commit}%)
            </td>
            <td style={RIGHT}>
              {formatBps(u.out_bps)} ({u.out_pct_of_commit}%)
            </td>
          </tr>
        ))}
      </tbody>
    </DataTable>
  );
}
