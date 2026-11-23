import { useState } from 'react';
import { Link } from 'react-router';

import { type EventQuery, useHardwareEvents } from '@/api/hardware';
import { CardHeader, CatalogueBody } from '@/components/CatalogueParts';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { Pager } from '@/components/Pager';
import { formatBackendTimestamp } from '@/lib/datetime';
import {
  eventFilterParam,
  HARDWARE_CATEGORIES,
  HARDWARE_EVENTS,
  HARDWARE_PAGE_SIZE,
  type HardwareCategory,
  type HardwareEventType,
} from '@/lib/hardware';
import { useDebouncedValue } from '@/lib/useDebouncedValue';

import { EventBadge, EventSentence } from './parts';

/**
 * The fleet's hardware changes, newest first. "All changes" (the default)
 * asks the server for every event type but the first read (baseline) of a
 * device; picking a type, "First read" included, asks for that type only.
 */
export function ChangesTab() {
  const [search, setSearch] = useState('');
  const [event, setEvent] = useState<HardwareEventType | ''>('');
  const [category, setCategory] = useState<HardwareCategory | ''>('');
  const [offset, setOffset] = useState(0);
  const debounced = useDebouncedValue(search.trim());

  const filter = { search: debounced, event: eventFilterParam(event), category };
  // A new filter starts again at the newest page (prev-value guard, no effect).
  const filterKey = JSON.stringify(filter);
  const [prevKey, setPrevKey] = useState(filterKey);
  if (filterKey !== prevKey) {
    setPrevKey(filterKey);
    setOffset(0);
  }
  const query: EventQuery = { ...filter, limit: HARDWARE_PAGE_SIZE, offset };
  const q = useHardwareEvents(query);
  const rows = q.data?.events ?? [];
  const total = q.data?.total ?? 0;
  const filtered = Boolean(debounced || event || category);

  return (
    <div className="stack">
      <div className="toolbar" style={{ flexWrap: 'wrap' }}>
        <input
          type="search"
          aria-label="Search changes"
          className="form-input form-input-sm"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Serial, model, name, slot or device"
          maxLength={200}
          style={{ flex: '1 1 220px', maxWidth: 340 }}
        />
        <select
          aria-label="Change"
          className="form-select form-select-sm"
          value={event}
          onChange={(e) => setEvent(e.target.value as HardwareEventType | '')}
        >
          <option value="">All changes</option>
          {HARDWARE_EVENTS.map((t) => (
            <option key={t.value} value={t.value}>
              {t.label}
            </option>
          ))}
        </select>
        <select
          aria-label="Category"
          className="form-select form-select-sm"
          value={category}
          onChange={(e) => setCategory(e.target.value as HardwareCategory | '')}
        >
          <option value="">All categories</option>
          {HARDWARE_CATEGORIES.map((c) => (
            <option key={c.value} value={c.value}>
              {c.label}
            </option>
          ))}
        </select>
      </div>

      <div className="card">
        <CardHeader
          title="Changes"
          sub={q.data && `${total.toLocaleString()} change${total === 1 ? '' : 's'}${filtered ? ' matching the filter' : ''}, newest first`}
        />
        <CatalogueBody
          query={{ ...q, data: q.data ? rows : undefined }}
          what="hardware changes"
          rows={rows}
          empty={
            <EmptyState
              compact
              message={filtered ? 'No change matches the filter.' : 'No hardware changes recorded yet.'}
              description={
                filtered ? undefined : 'Changes appear when a module is installed, removed, moved or replaced on a device.'
              }
            />
          }
        >
          <DataTable compact aria-label="Hardware changes">
            <thead>
              <tr>
                <th>Time</th>
                <th>Device</th>
                <th>Change</th>
                <th>What happened</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((e) => (
                <tr key={e.id}>
                  <td style={{ whiteSpace: 'nowrap' }}>{formatBackendTimestamp(e.occurred_at)}</td>
                  <td>
                    {e.host_id !== null ? (
                      <Link to={`/devices/${e.host_id}`} style={{ fontWeight: 600 }}>
                        {e.hostname || `Host ${e.host_id}`}
                      </Link>
                    ) : (
                      e.hostname || '-'
                    )}
                  </td>
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
          <Pager offset={offset} pageSize={HARDWARE_PAGE_SIZE} total={total} onChange={setOffset} />
        </CatalogueBody>
      </div>
    </div>
  );
}
