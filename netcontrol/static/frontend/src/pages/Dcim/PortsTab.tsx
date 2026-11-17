import { useState } from 'react';
import { Link } from 'react-router';

import type { DcimRecord } from '@/api/dcim';
import { Dash } from '@/components/CatalogueParts';
import { traceLink } from '@/lib/dcim';

import { type Option, useChoices, useHostOptions, useRecordOptions } from './hooks';
import { RecordSection, Val } from './RecordSection';

const rearLabel = (r: Record<string, unknown>) => `${String(r.host_name)} / ${String(r.name)} (${String(r.positions)})`;

/** A device picker that filters the tables below it. */
export function HostFilter({
  value,
  onChange,
  hosts,
}: {
  value: number | null;
  onChange: (v: number | null) => void;
  hosts: Option[];
}) {
  return (
    <div className="form-group" style={{ maxWidth: '20rem' }}>
      <label className="form-label" htmlFor="dcim-host-filter">
        Device
      </label>
      <select
        id="dcim-host-filter"
        className="form-select"
        value={value ?? ''}
        onChange={(e) => onChange(e.target.value ? Number(e.target.value) : null)}
      >
        <option value="">All devices</option>
        {hosts.map((h) => (
          <option key={h.value} value={h.value}>
            {h.label}
          </option>
        ))}
      </select>
    </div>
  );
}

/** The cable on a port, with a trace link. */
export function CableCell({
  row,
  type,
}: {
  row: DcimRecord;
  type: 'front_port' | 'rear_port' | 'power_port' | 'power_outlet' | 'power_feed';
}) {
  if (!row.cable_id) return <Dash />;
  return <Link to={traceLink({ type, id: row.id })}>{String(row.cable_label || `#${String(row.cable_id)}`)} (trace)</Link>;
}

/** The DCIM page's Patch panels tab: rear ports (with positions) and the front ports mapped onto them. */
export function PortsTab() {
  const hosts = useHostOptions();
  const choices = useChoices();
  const [hostId, setHostId] = useState<number | null>(null);
  const rears = useRecordOptions('rear_port', rearLabel);
  const portTypes = choices('port_types');
  return (
    <div>
      <HostFilter value={hostId} onChange={setHostId} hosts={hosts} />
      <RecordSection
        kind="rear_port"
        title="Rear ports"
        what="rear port"
        filters={{ host_id: hostId }}
        emptyText="No rear ports yet. A patch panel is a device with rear and front ports."
        fields={[
          {
            key: 'host_id',
            label: 'Device',
            kind: 'ref',
            options: hosts,
            required: true,
            initial: hostId,
            createOnly: true,
          },
          { key: 'name', label: 'Name', kind: 'text', required: true },
          {
            key: 'type',
            label: 'Connector',
            kind: 'select',
            options: portTypes,
            initial: '8p8c',
          },
          {
            key: 'positions',
            label: 'Positions',
            kind: 'number',
            initial: 1,
            min: 1,
            max: 1024,
            required: true,
          },
          { key: 'description', label: 'Description', kind: 'text' },
        ]}
        columns={[
          { label: 'Device', render: (r) => <Val value={r.host_name} /> },
          { label: 'Name', render: (r) => String(r.name) },
          { label: 'Connector', render: (r) => <Val value={r.type} /> },
          {
            label: 'Positions',
            render: (r) => <Val value={r.positions} />,
            align: 'right',
          },
          {
            label: 'Front ports',
            render: (r) => <Val value={r.front_port_count} />,
            align: 'right',
          },
          {
            label: 'Cable',
            render: (r) => <CableCell row={r} type="rear_port" />,
          },
        ]}
      />
      <RecordSection
        kind="front_port"
        title="Front ports"
        what="front port"
        filters={{ host_id: hostId }}
        emptyText="No front ports yet."
        fields={[
          {
            key: 'host_id',
            label: 'Device',
            kind: 'ref',
            options: hosts,
            required: true,
            initial: hostId,
            createOnly: true,
          },
          { key: 'name', label: 'Name', kind: 'text', required: true },
          {
            key: 'type',
            label: 'Connector',
            kind: 'select',
            options: portTypes,
            initial: '8p8c',
          },
          {
            key: 'rear_port_id',
            label: 'Rear port',
            kind: 'ref',
            options: rears,
            required: true,
            help: 'A rear port of the same device.',
          },
          {
            key: 'rear_port_position',
            label: 'Rear port position',
            kind: 'number',
            initial: 1,
            min: 1,
            max: 1024,
            required: true,
          },
          { key: 'description', label: 'Description', kind: 'text' },
        ]}
        columns={[
          { label: 'Device', render: (r) => <Val value={r.host_name} /> },
          { label: 'Name', render: (r) => String(r.name) },
          { label: 'Connector', render: (r) => <Val value={r.type} /> },
          {
            label: 'Rear port',
            render: (r) => `${String(r.rear_port_name)} : ${String(r.rear_port_position)}`,
          },
          {
            label: 'Cable',
            render: (r) => <CableCell row={r} type="front_port" />,
          },
        ]}
      />
    </div>
  );
}

/** The DCIM page's Modules tab: the modules installed in device bays. */
export function ModulesTab() {
  const hosts = useHostOptions();
  const choices = useChoices();
  const [hostId, setHostId] = useState<number | null>(null);
  return (
    <div>
      <HostFilter value={hostId} onChange={setHostId} hosts={hosts} />
      <RecordSection
        kind="module"
        title="Modules"
        what="module"
        filters={{ host_id: hostId }}
        nameOf={(r) => String(r.bay)}
        emptyText="No modules yet."
        fields={[
          {
            key: 'host_id',
            label: 'Device',
            kind: 'ref',
            options: hosts,
            required: true,
            initial: hostId,
            createOnly: true,
          },
          { key: 'bay', label: 'Bay', kind: 'text', required: true },
          { key: 'module_type', label: 'Module type', kind: 'text' },
          { key: 'part_number', label: 'Part number', kind: 'text' },
          { key: 'serial', label: 'Serial', kind: 'text' },
          { key: 'asset_tag', label: 'Asset tag', kind: 'text' },
          {
            key: 'status',
            label: 'Status',
            kind: 'select',
            options: choices('module_statuses'),
            initial: 'active',
          },
          { key: 'description', label: 'Description', kind: 'text' },
        ]}
        columns={[
          { label: 'Device', render: (r) => <Val value={r.host_name} /> },
          { label: 'Bay', render: (r) => String(r.bay) },
          { label: 'Type', render: (r) => <Val value={r.module_type} /> },
          {
            label: 'Part number',
            render: (r) => <Val value={r.part_number} />,
          },
          { label: 'Serial', render: (r) => <Val value={r.serial} /> },
          { label: 'Status', render: (r) => <Val value={r.status} /> },
        ]}
      />
    </div>
  );
}
