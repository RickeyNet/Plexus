import { useId, useState } from 'react';
import { Link } from 'react-router';

import { type ElevationBlock, usePlaceHost, useRackElevation, useRackPower } from '@/api/dcim';
import { Callout } from '@/components/Callout';
import { ChangelogPanel } from '@/components/ChangelogPanel';
import { DataTable } from '@/components/DataTable';
import { FieldError } from '@/components/FieldError';
import { LoadingState } from '@/components/LoadingState';
import { ProgressBar } from '@/components/ProgressBar';
import { QueryError } from '@/components/QueryError';
import { ObjectDataPanel } from '@/components/ObjectDataPanel';
import { blockUnitsLabel, type FieldSpec, formatUnits, formatWatts } from '@/lib/dcim';
import { utilizationTone } from '@/lib/severity';

import { type Option, useCanWriteDcim, useChoices, useHostOptions, useRecordOptions, useSiteOptions } from './hooks';
import { RecordSection, Val } from './RecordSection';

const UNIT_PX = 22;

const roleLabel = (r: Record<string, unknown>) => String(r.name);

/** The DCIM page's Racks tab: racks, the selected rack's elevation, reservations and power, and rack roles. */
export function RacksTab() {
  const [selected, setSelected] = useState<number | null>(null);
  const [siteId, setSiteId] = useState<number | null>(null);
  const sites = useSiteOptions();
  const roles = useRecordOptions('rack_role', roleLabel);
  const choices = useChoices();
  const fields: FieldSpec[] = [
    {
      key: 'site_id',
      label: 'Site',
      kind: 'ref',
      options: sites,
      required: true,
      initial: siteId,
    },
    { key: 'name', label: 'Name', kind: 'text', required: true },
    {
      key: 'status',
      label: 'Status',
      kind: 'select',
      options: choices('rack_statuses'),
      initial: 'active',
    },
    { key: 'role_id', label: 'Role', kind: 'ref', options: roles },
    {
      key: 'u_height',
      label: 'Height (units)',
      kind: 'number',
      required: true,
      initial: 42,
      min: 1,
      max: 100,
    },
    { key: 'desc_units', label: 'Number units from the top', kind: 'checkbox' },
    {
      key: 'width',
      label: 'Width (inches)',
      kind: 'select',
      options: ['19', '23'],
      initial: '19',
    },
    { key: 'facility_id', label: 'Facility ID', kind: 'text' },
    { key: 'serial', label: 'Serial', kind: 'text' },
    { key: 'asset_tag', label: 'Asset tag', kind: 'text' },
    { key: 'tenant_id', label: 'Tenant', kind: 'tenant' },
    { key: 'description', label: 'Description', kind: 'text' },
    { key: 'comments', label: 'Comments', kind: 'textarea' },
  ];
  return (
    <div
      style={{
        display: 'grid',
        gap: '1rem',
        gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 30rem), 1fr))',
      }}
    >
      <div>
        <div className="form-group" style={{ maxWidth: '20rem' }}>
          <label className="form-label" htmlFor="dcim-rack-site">
            Site
          </label>
          <select
            id="dcim-rack-site"
            className="form-select"
            value={siteId ?? ''}
            onChange={(e) => setSiteId(e.target.value ? Number(e.target.value) : null)}
          >
            <option value="">All sites</option>
            {sites.map((s) => (
              <option key={s.value} value={s.value}>
                {s.label}
              </option>
            ))}
          </select>
        </div>
        <RecordSection
          kind="rack"
          title="Racks"
          what="rack"
          filters={{ site_id: siteId }}
          fields={fields}
          emptyText="No racks yet. Add one to place devices by unit."
          onSelect={(r) => setSelected(r.id)}
          selectedId={selected}
          columns={[
            { label: 'Name', render: (r) => <strong>{String(r.name)}</strong> },
            { label: 'Site', render: (r) => <Val value={r.site_name} /> },
            { label: 'Status', render: (r) => <Val value={r.status} /> },
            { label: 'Role', render: (r) => <Val value={r.role_name} /> },
            {
              label: 'Units',
              render: (r) => <Val value={r.u_height} />,
              align: 'right',
            },
            {
              label: 'Devices',
              render: (r) => <Val value={r.device_count} />,
              align: 'right',
            },
          ]}
        />
        <RecordSection
          kind="rack_role"
          title="Rack roles"
          what="rack role"
          emptyText="No rack roles yet."
          fields={[
            { key: 'name', label: 'Name', kind: 'text', required: true },
            {
              key: 'color',
              label: 'Color',
              kind: 'select',
              options: ['gray', 'red', 'orange', 'yellow', 'green', 'teal', 'blue', 'purple'],
              initial: 'gray',
            },
            { key: 'description', label: 'Description', kind: 'text' },
          ]}
          columns={[
            { label: 'Name', render: (r) => String(r.name) },
            { label: 'Color', render: (r) => <Val value={r.color} /> },
            {
              label: 'Racks',
              render: (r) => <Val value={r.rack_count} />,
              align: 'right',
            },
          ]}
        />
      </div>
      <div>
        {selected === null ? <p className="text-muted">Select a rack to see its elevation.</p> : <RackDetail rackId={selected} />}
      </div>
    </div>
  );
}

function RackDetail({ rackId }: { rackId: number }) {
  const q = useRackElevation(rackId);
  const [face, setFace] = useState<'front' | 'rear'>('front');
  const [placeAt, setPlaceAt] = useState<number | null>(null);
  if (q.isError && !q.data) return <QueryError what="rack elevation" query={q} />;
  if (q.isPending) return <LoadingState text="Loading rack…" />;
  const e = q.data;
  const rack = e.rack;
  return (
    <div style={{ display: 'grid', gap: '1rem' }}>
      <div className="card">
        <h3 style={{ margin: 0 }}>
          Rack {String(rack.name)} <span className="text-muted">· {String(rack.site_name)}</span>
        </h3>
        <div className="text-muted" style={{ fontSize: '0.9em' }}>
          {e.u_height}U · {e.used_units} used · {e.free_units} free
        </div>
        <div className="tab-bar tab-bar-sm" role="tablist" aria-label="Rack face" style={{ margin: '0.75rem 0' }}>
          {(['front', 'rear'] as const).map((f) => (
            <button
              key={f}
              type="button"
              role="tab"
              aria-selected={face === f}
              className={`btn btn-sm btn-secondary page-tab-btn${face === f ? ' active' : ''}`}
              onClick={() => setFace(f)}
            >
              {f === 'front' ? 'Front' : 'Rear'}
            </button>
          ))}
        </div>
        <Elevation blocks={e.faces[face]} onEmptyClick={setPlaceAt} />
        {e.unmounted.length > 0 && (
          <Callout tone="warning" title="In the rack but not mounted">
            {e.unmounted.map((d) => d.name).join(', ')}
          </Callout>
        )}
      </div>
      <PlaceDevice rackId={rackId} face={face} position={placeAt} onPosition={setPlaceAt} />
      <RecordSection
        kind="rack_reservation"
        title="Reservations"
        what="reservation"
        filters={{ rack_id: rackId }}
        nameOf={(r) => formatUnits((r.units as number[]) ?? [])}
        emptyText="No units reserved."
        fields={[
          {
            key: 'rack_id',
            label: 'Rack',
            kind: 'ref',
            options: [{ value: rackId, label: String(rack.name) }],
            initial: rackId,
            required: true,
            createOnly: true,
          },
          {
            key: 'units',
            label: 'Units',
            kind: 'units',
            required: true,
            help: 'Units such as 1-3, 7.',
          },
          { key: 'user', label: 'Reserved for', kind: 'text' },
          { key: 'description', label: 'Description', kind: 'text' },
          { key: 'tenant_id', label: 'Tenant', kind: 'tenant' },
        ]}
        columns={[
          {
            label: 'Units',
            render: (r) => formatUnits((r.units as number[]) ?? []),
          },
          { label: 'For', render: (r) => <Val value={r.user} /> },
          {
            label: 'Description',
            render: (r) => <Val value={r.description} />,
          },
        ]}
      />
      <RackPowerCard rackId={rackId} />
      <div className="card">
        <ChangelogPanel objectType="rack" objectId={rackId} pageSize={10} />
      </div>
      <ObjectDataPanel objectType="rack" objectId={rackId} />
    </div>
  );
}

/** One face of a rack: a column of unit rows, devices and reservations spanning theirs. */
export function Elevation({ blocks, onEmptyClick }: { blocks: ElevationBlock[]; onEmptyClick?: (unit: number) => void }) {
  return (
    <div
      role="list"
      aria-label="Rack units"
      style={{
        border: '1px solid var(--border-color, #444)',
        borderRadius: 4,
        maxWidth: 420,
      }}
    >
      {blocks.map((b) => {
        const style = {
          height: b.height * UNIT_PX,
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          padding: '0 0.5rem',
          borderBottom: '1px solid var(--border-color, #444)',
          fontSize: '0.85em',
          boxSizing: 'border-box' as const,
        };
        const units = (
          <span className="text-muted" style={{ width: '4.5rem', flexShrink: 0 }}>
            {blockUnitsLabel(b.units)}
          </span>
        );
        if (b.kind === 'device') {
          return (
            <div
              key={`d-${b.host_id}`}
              role="listitem"
              style={{
                ...style,
                background: b.mounted_here ? 'var(--accent-bg, rgba(80,140,255,0.25))' : 'rgba(128,128,128,0.18)',
              }}
            >
              {units}
              <Link to={`/devices/${b.host_id}`}>{b.name}</Link>
              {!b.mounted_here && <span className="text-muted">(mounted {b.face})</span>}
            </div>
          );
        }
        if (b.kind === 'reservation') {
          return (
            <div
              key={`r-${b.reservation_id}-${b.units[0]}`}
              role="listitem"
              style={{ ...style, background: 'rgba(255,190,60,0.18)' }}
            >
              {units}
              <span>Reserved{b.description ? `: ${b.description}` : ''}</span>
            </div>
          );
        }
        return (
          <div key={`e-${b.units[0]}`} role="listitem" style={style}>
            {units}
            {onEmptyClick && (
              <button
                type="button"
                className="btn btn-sm btn-secondary"
                style={{ padding: '0 0.4rem' }}
                onClick={() => onEmptyClick(b.units[0])}
              >
                Place here
              </button>
            )}
          </div>
        );
      })}
    </div>
  );
}

function PlaceDevice({
  rackId,
  face,
  position,
  onPosition,
}: {
  rackId: number;
  face: 'front' | 'rear';
  position: number | null;
  onPosition: (unit: number | null) => void;
}) {
  const id = useId();
  const canWrite = useCanWriteDcim();
  const hosts: Option[] = useHostOptions();
  const place = usePlaceHost();
  const [hostId, setHostId] = useState('');
  const [error, setError] = useState<string | null>(null);
  if (!canWrite) return null;
  const submit = async () => {
    setError(null);
    if (!hostId) {
      setError('Choose a device.');
      return;
    }
    try {
      await place.mutateAsync({
        hostId: Number(hostId),
        rack_id: rackId,
        rack_position: position,
        rack_face: position ? face : null,
      });
      onPosition(null);
      setHostId('');
    } catch (err) {
      setError((err as Error).message);
    }
  };
  return (
    <div className="card">
      <h4 style={{ marginTop: 0 }}>Place a device</h4>
      <div
        style={{
          display: 'flex',
          gap: '0.5rem',
          flexWrap: 'wrap',
          alignItems: 'flex-end',
        }}
      >
        <div className="form-group">
          <label className="form-label" htmlFor={`${id}-host`}>
            Device
          </label>
          <select id={`${id}-host`} className="form-select" value={hostId} onChange={(e) => setHostId(e.target.value)}>
            <option value="">Choose…</option>
            {hosts.map((h) => (
              <option key={h.value} value={h.value}>
                {h.label}
              </option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${id}-unit`}>
            Lowest unit (empty: not mounted)
          </label>
          <input
            id={`${id}-unit`}
            className="form-input"
            type="number"
            min={1}
            style={{ width: '7rem' }}
            value={position ?? ''}
            onChange={(e) => onPosition(e.target.value ? Number(e.target.value) : null)}
          />
        </div>
        <div className="form-group">
          <button type="button" className="btn btn-primary" disabled={place.isPending} onClick={() => void submit()}>
            Place on {face}
          </button>
        </div>
      </div>
      <FieldError>{error}</FieldError>
    </div>
  );
}

function RackPowerCard({ rackId }: { rackId: number }) {
  const q = useRackPower(rackId);
  if (q.isError && !q.data) return <QueryError what="rack power" query={q} />;
  if (q.isPending) return <LoadingState text="Loading power…" />;
  const p = q.data;
  return (
    <div className="card">
      <h4 style={{ marginTop: 0 }}>Power</h4>
      <p style={{ margin: '0 0 0.5rem' }}>
        {formatWatts(p.allocated_draw)} allocated of {formatWatts(p.capacity)} usable
        {p.utilization !== null && (
          <>
            {' '}
            · {p.utilization}%
            <ProgressBar
              value={p.utilization}
              tone={utilizationTone(p.utilization)}
              size="sm"
              label="Rack power use"
              style={{
                width: 96,
                display: 'inline-block',
                marginLeft: '0.5rem',
                verticalAlign: 'middle',
              }}
            />
          </>
        )}
        {p.unfed_draw > 0 && <span className="text-muted"> · {formatWatts(p.unfed_draw)} not traced to a feed</span>}
      </p>
      {p.feeds.length === 0 ? (
        <p className="text-muted" style={{ margin: 0 }}>
          No power feed is assigned to this rack.
        </p>
      ) : (
        <DataTable compact aria-label="Rack feeds">
          <thead>
            <tr>
              <th>Feed</th>
              <th>Type</th>
              <th style={{ textAlign: 'right' }}>Usable</th>
              <th style={{ textAlign: 'right' }}>Allocated</th>
              <th style={{ textAlign: 'right' }}>Use</th>
            </tr>
          </thead>
          <tbody>
            {p.feeds.map((f) => (
              <tr key={f.id}>
                <td>{f.name}</td>
                <td>{f.type}</td>
                <td style={{ textAlign: 'right' }}>{formatWatts(f.available_power)}</td>
                <td style={{ textAlign: 'right' }}>{formatWatts(f.allocated_draw)}</td>
                <td style={{ textAlign: 'right' }}>{f.utilization === null ? '-' : `${f.utilization}%`}</td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      )}
    </div>
  );
}
