import { useId, useMemo, useState } from 'react';

import { useAuthStatus } from '@/api/auth';
import {
  type HardwareComponent,
  type HostHardware,
  useHostHardware,
  useHostHardwareEvents,
  useRefreshHostHardware,
} from '@/api/hardware';
import { BusyButton } from '@/components/BusyButton';
import { Callout } from '@/components/Callout';
import { Dash } from '@/components/CatalogueParts';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { formatBackendDateTime, formatBackendTimestamp } from '@/lib/datetime';
import { categoryLabel, HARDWARE_CATEGORIES, type HardwareCategory, visibleComponents } from '@/lib/hardware';
import { canWriteFeature } from '@/lib/tabGating';
import { ComponentStatusBadge, EventBadge, EventSentence, Revisions, Serial } from '@/pages/Hardware/parts';

const SOURCE_LABEL: Record<string, string> = { snmp: 'SNMP', ssh: 'SSH' };

/**
 * The device page's Hardware tab: the components read from the device
 * (chassis, modules, power supplies, fans, transceivers) with their serials,
 * and below them every change to them, newest first.
 */
export function HardwareTab({ hostId }: { hostId: number }) {
  const hardware = useHostHardware(hostId);
  return (
    <div className="stack">
      <StatusLine hostId={hostId} hardware={hardware.data} />
      {hardware.isError && !hardware.data ? (
        <QueryError what="the hardware of this device" query={hardware} />
      ) : hardware.isPending ? (
        <LoadingState text="Loading hardware…" />
      ) : (
        <ComponentsSection components={hardware.data.components} />
      )}
      <HistorySection hostId={hostId} />
    </div>
  );
}

/** When the hardware was last read and from where, why it was not, and the refresh button. */
export function StatusLine({ hostId, hardware }: { hostId: number; hardware: HostHardware | undefined }) {
  const canWrite = canWriteFeature('inventory', useAuthStatus().data);
  const refresh = useRefreshHostHardware(hostId);
  const read = hardware?.collected_at
    ? `Hardware last read ${formatBackendDateTime(hardware.collected_at)}${
        hardware.source ? ` over ${SOURCE_LABEL[hardware.source] ?? hardware.source}` : ''
      }.`
    : hardware
      ? 'Hardware not read yet.'
      : '';
  return (
    <div className="stack stack-sm">
      <div className="toolbar" style={{ flexWrap: 'wrap' }}>
        <span className="text-muted" style={{ fontSize: '0.88em' }}>
          {read} Plexus reads it by SNMP every 6 hours and after a module or restart event.
        </span>
        <span className="toolbar-spacer" />
        {canWrite && (
          <BusyButton
            className="btn btn-sm btn-secondary"
            busy={refresh.isPending}
            busyLabel="Reading…"
            onClick={() => refresh.mutate()}
          >
            Refresh hardware
          </BusyButton>
        )}
      </div>
      {hardware && hardware.state !== 'ok' && hardware.message && (
        <Callout tone={hardware.state === 'never' ? 'info' : 'warning'}>{hardware.message}</Callout>
      )}
      {refresh.isError && (
        <Callout tone="danger" title="The hardware was not read">
          {refresh.error.message}
        </Callout>
      )}
    </div>
  );
}

// ── Components ─────────────────────────────────────────────────────────────

export function ComponentsSection({ components }: { components: HardwareComponent[] }) {
  const fid = useId();
  const [category, setCategory] = useState<HardwareCategory | ''>('');
  const [text, setText] = useState('');
  const [showRemoved, setShowRemoved] = useState(false);

  const rows = useMemo(
    () => visibleComponents(components, { category, text, showRemoved }),
    [components, category, text, showRemoved],
  );
  const removedCount = components.filter((c) => c.status === 'removed').length;
  const missingCount = components.filter((c) => c.status === 'missing').length;
  const counts = useMemo(() => {
    const out = new Map<string, number>();
    for (const c of components) if (showRemoved || c.status !== 'removed') out.set(c.category, (out.get(c.category) ?? 0) + 1);
    return out;
  }, [components, showRemoved]);
  const groups = useMemo(() => {
    const out: { category: string; rows: HardwareComponent[] }[] = [];
    for (const c of rows) {
      const last = out[out.length - 1];
      if (last && last.category === c.category) last.rows.push(c);
      else out.push({ category: c.category, rows: [c] });
    }
    return out;
  }, [rows]);

  if (components.length === 0) {
    return (
      <EmptyState
        compact
        message="No hardware components recorded for this device."
        description="Components appear after the first hardware read. Devices whose SNMP agent has no entity table list none."
      />
    );
  }
  const filtered = Boolean(category || text.trim());

  return (
    <section aria-label="Components" className="stack stack-sm">
      <div className="toolbar" style={{ flexWrap: 'wrap', alignItems: 'center' }}>
        <select
          id={`${fid}-category`}
          aria-label="Category"
          className="form-select form-select-sm"
          value={category}
          onChange={(e) => setCategory(e.target.value as HardwareCategory | '')}
        >
          <option value="">All categories</option>
          {HARDWARE_CATEGORIES.filter((c) => counts.has(c.value)).map((c) => (
            <option key={c.value} value={c.value}>
              {c.label} ({counts.get(c.value)})
            </option>
          ))}
        </select>
        <input
          type="search"
          aria-label="Filter components"
          className="form-input form-input-sm"
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Slot, name, model or serial"
          style={{ flex: '1 1 200px', maxWidth: 320 }}
        />
        {removedCount > 0 && (
          <label className="text-muted" style={{ display: 'flex', gap: '0.3rem', alignItems: 'center' }}>
            <input type="checkbox" checked={showRemoved} onChange={(e) => setShowRemoved(e.target.checked)} />
            Show removed ({removedCount})
          </label>
        )}
      </div>
      {missingCount > 0 && (
        <Callout tone="warning">
          {missingCount === 1 ? '1 component was' : `${missingCount} components were`} not in the last read. Plexus reads
          the device again at every poll, and records {missingCount === 1 ? 'it' : 'them'} as removed when{' '}
          {missingCount === 1 ? 'it has' : 'they have'} been absent for 30 minutes.
        </Callout>
      )}
      {rows.length === 0 ? (
        <EmptyState
          compact
          message={filtered ? 'No component matches the filter.' : 'Every component of this device has been removed.'}
        />
      ) : (
        groups.map((g) => (
          <div key={g.category}>
            <div style={{ fontWeight: 600, margin: 'var(--space-2) 0 var(--space-1)' }}>
              {categoryLabel(g.category)} <span className="text-muted">({g.rows.length})</span>
            </div>
            <ComponentTable rows={g.rows} label={categoryLabel(g.category)} />
          </div>
        ))
      )}
    </section>
  );
}

function ComponentTable({ rows, label }: { rows: HardwareComponent[]; label: string }) {
  return (
    <DataTable compact aria-label={label}>
      <thead>
        <tr>
          <th>Slot</th>
          <th>Name</th>
          <th>Model</th>
          <th>Serial</th>
          <th>Revision</th>
          <th>First seen</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((c) => (
          <tr key={c.id} className={c.status === 'removed' ? 'text-muted' : undefined}>
            <td style={{ whiteSpace: 'nowrap' }}>{c.slot || <Dash />}</td>
            <td style={{ minWidth: 180 }}>
              {c.name || <Dash />}
              {c.description && c.description !== c.name && (
                <div className="text-muted" style={{ fontSize: '0.85em' }}>
                  {c.description}
                </div>
              )}
            </td>
            <td>{c.model || <Dash />}</td>
            <td>
              <Serial value={c.serial} />
            </td>
            <td style={{ fontSize: '0.88em' }}>
              <Revisions component={c} />
            </td>
            <td style={{ whiteSpace: 'nowrap' }}>{formatBackendDateTime(c.first_seen)}</td>
            <td>
              <span
                title={
                  c.status === 'missing'
                    ? `Not in the last read; last seen ${formatBackendDateTime(c.last_seen)}.`
                    : c.status === 'removed'
                      ? `Removed ${formatBackendDateTime(c.removed_at)}.`
                      : undefined
                }
              >
                <ComponentStatusBadge status={c.status} />
              </span>
              {c.status === 'removed' && c.removed_at && (
                <div className="text-muted" style={{ fontSize: '0.85em', whiteSpace: 'nowrap' }}>
                  {formatBackendDateTime(c.removed_at)}
                </div>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </DataTable>
  );
}

// ── History ────────────────────────────────────────────────────────────────

function HistorySection({ hostId }: { hostId: number }) {
  const q = useHostHardwareEvents(hostId);
  const events = q.data?.pages.flatMap((p) => p.events) ?? [];
  const total = q.data?.pages[q.data.pages.length - 1]?.total ?? 0;

  let body;
  if (q.isError && !q.data) body = <QueryError what="the hardware history" query={q} />;
  else if (q.isPending) body = <LoadingState text="Loading hardware history…" />;
  else if (events.length === 0) {
    body = <EmptyState compact message="No hardware changes recorded for this device." />;
  } else {
    body = (
      <>
        <DataTable compact aria-label="Hardware changes">
          <thead>
            <tr>
              <th>Time</th>
              <th>Change</th>
              <th>What happened</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id}>
                <td style={{ whiteSpace: 'nowrap' }}>{formatBackendTimestamp(e.occurred_at)}</td>
                <td>
                  <EventBadge event={e.event} />
                </td>
                <td style={{ minWidth: 260, wordBreak: 'break-word' }}>
                  <EventSentence event={e} />
                </td>
              </tr>
            ))}
          </tbody>
        </DataTable>
        <div className="toolbar" style={{ justifyContent: 'space-between', marginTop: 'var(--space-2)' }}>
          <span className="text-muted" style={{ fontSize: '0.85em' }}>
            {events.length.toLocaleString()} of {total.toLocaleString()} changes
          </span>
          {q.hasNextPage && (
            <BusyButton
              className="btn btn-sm btn-secondary"
              busy={q.isFetchingNextPage}
              busyLabel="Loading…"
              onClick={() => void q.fetchNextPage()}
            >
              Load more
            </BusyButton>
          )}
        </div>
        {q.isFetchNextPageError && <QueryError what="more changes" error={q.error} onRetry={() => void q.fetchNextPage()} />}
      </>
    );
  }

  return (
    <section aria-label="Hardware history">
      <div style={{ fontWeight: 600, marginBottom: '0.45rem' }}>Change history</div>
      {body}
    </section>
  );
}
