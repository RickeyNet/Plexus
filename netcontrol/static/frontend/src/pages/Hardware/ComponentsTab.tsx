import { useState } from 'react';
import { Link } from 'react-router';

import { useInventoryGroups } from '@/api/compliance';
import { type ComponentQuery, hardwareExportUrl, useHardwareComponents } from '@/api/hardware';
import { groupLabel } from '@/api/inventory';
import { CardHeader, CatalogueBody, Dash } from '@/components/CatalogueParts';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { Pager } from '@/components/Pager';
import { formatBackendDateTime } from '@/lib/datetime';
import {
  categoryLabel,
  COMPONENT_STATUSES,
  type ComponentStatus,
  HARDWARE_CATEGORIES,
  HARDWARE_PAGE_SIZE,
  type HardwareCategory,
} from '@/lib/hardware';
import { useDebouncedValue } from '@/lib/useDebouncedValue';

import { ComponentStatusBadge, Revisions, Serial } from './parts';

/** Every component across the fleet: server searched, filtered and paged. */
export function ComponentsTab() {
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState<HardwareCategory | ''>('');
  const [status, setStatus] = useState<ComponentStatus | ''>('');
  const [groupId, setGroupId] = useState<number | null>(null);
  const [offset, setOffset] = useState(0);
  const debounced = useDebouncedValue(search.trim());
  const groups = useInventoryGroups();

  const filter = { search: debounced, category, status, group_id: groupId };
  // A new filter starts again at the first page (prev-value guard, no effect).
  const filterKey = JSON.stringify(filter);
  const [prevKey, setPrevKey] = useState(filterKey);
  if (filterKey !== prevKey) {
    setPrevKey(filterKey);
    setOffset(0);
  }
  const query: ComponentQuery = { ...filter, limit: HARDWARE_PAGE_SIZE, offset };
  const q = useHardwareComponents(query);
  const rows = q.data?.components ?? [];
  const total = q.data?.total ?? 0;
  const filtered = Boolean(debounced || category || status || groupId !== null);

  return (
    <div className="stack">
      <div className="toolbar" style={{ flexWrap: 'wrap' }}>
        <input
          type="search"
          aria-label="Search components"
          className="form-input form-input-sm"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Serial, model, name, slot or device"
          maxLength={200}
          style={{ flex: '1 1 220px', maxWidth: 340 }}
        />
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
        <select
          aria-label="Status"
          className="form-select form-select-sm"
          value={status}
          onChange={(e) => setStatus(e.target.value as ComponentStatus | '')}
        >
          <option value="">All statuses</option>
          {COMPONENT_STATUSES.map((s) => (
            <option key={s.value} value={s.value}>
              {s.label}
            </option>
          ))}
        </select>
        <select
          aria-label="Group"
          className="form-select form-select-sm"
          value={groupId ?? ''}
          onChange={(e) => setGroupId(e.target.value ? Number(e.target.value) : null)}
        >
          <option value="">All groups</option>
          {(groups.data ?? []).map((g) => (
            <option key={g.id} value={g.id}>
              {groupLabel(g)}
            </option>
          ))}
        </select>
        <span className="toolbar-spacer" />
        <a className="btn btn-sm btn-secondary" href={hardwareExportUrl(filter)} download>
          Export CSV
        </a>
      </div>

      <div className="card">
        <CardHeader
          title="Components"
          sub={q.data && `${total.toLocaleString()} component${total === 1 ? '' : 's'}${filtered ? ' matching the filter' : ''}`}
        />
        <CatalogueBody
          query={{ ...q, data: q.data ? rows : undefined }}
          what="hardware components"
          rows={rows}
          empty={
            <EmptyState
              compact
              message={filtered ? 'No component matches the filter.' : 'No hardware components recorded yet.'}
              description={
                filtered
                  ? undefined
                  : 'Components appear after the first hardware read of a device. Plexus reads them by SNMP every 6 hours.'
              }
            />
          }
        >
          <DataTable compact aria-label="Hardware components">
            <thead>
              <tr>
                <th>Device</th>
                <th>Category</th>
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
                  <td>
                    <Link to={`/devices/${c.host_id}`} style={{ fontWeight: 600 }}>
                      {c.hostname || `Host ${c.host_id}`}
                    </Link>
                  </td>
                  <td>{categoryLabel(c.category)}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>{c.slot || <Dash />}</td>
                  <td style={{ minWidth: 160 }}>
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
                    <ComponentStatusBadge status={c.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </DataTable>
          <Pager
            offset={offset}
            pageSize={HARDWARE_PAGE_SIZE}
            total={total}
            onChange={setOffset}
            previousLabel="Previous"
            nextLabel="Next"
          />
        </CatalogueBody>
      </div>
    </div>
  );
}
