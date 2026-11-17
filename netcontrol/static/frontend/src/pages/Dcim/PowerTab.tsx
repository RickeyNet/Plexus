import { useState } from 'react';

import { formatWatts } from '@/lib/dcim';

import { useChoices, useHostOptions, useRecordOptions, useSiteOptions } from './hooks';
import { CableCell, HostFilter } from './PortsTab';
import { RecordSection, Val } from './RecordSection';

const named = (r: Record<string, unknown>) => String(r.name);
const rackLabel = (r: Record<string, unknown>) => `${String(r.site_name)} / ${String(r.name)}`;
const portLabel = (r: Record<string, unknown>) => `${String(r.host_name)} / ${String(r.name)}`;

/** The DCIM page's Power tab: panels, feeds (with usable watts), device power ports and PDU outlets. */
export function PowerTab() {
  const sites = useSiteOptions();
  const hosts = useHostOptions();
  const panels = useRecordOptions('power_panel', named);
  const racks = useRecordOptions('rack', rackLabel);
  const ports = useRecordOptions('power_port', portLabel);
  const choices = useChoices();
  const [hostId, setHostId] = useState<number | null>(null);
  return (
    <div>
      <RecordSection
        kind="power_panel"
        title="Power panels"
        what="power panel"
        emptyText="No power panels yet."
        fields={[
          {
            key: 'site_id',
            label: 'Site',
            kind: 'ref',
            options: sites,
            required: true,
            createOnly: true,
          },
          { key: 'name', label: 'Name', kind: 'text', required: true },
          { key: 'description', label: 'Description', kind: 'text' },
        ]}
        columns={[
          { label: 'Name', render: (r) => String(r.name) },
          { label: 'Site', render: (r) => <Val value={r.site_name} /> },
          {
            label: 'Feeds',
            render: (r) => <Val value={r.feed_count} />,
            align: 'right',
          },
        ]}
      />
      <RecordSection
        kind="power_feed"
        title="Power feeds"
        what="power feed"
        emptyText="No power feeds yet."
        fields={[
          {
            key: 'power_panel_id',
            label: 'Panel',
            kind: 'ref',
            options: panels,
            required: true,
            createOnly: true,
          },
          { key: 'name', label: 'Name', kind: 'text', required: true },
          {
            key: 'rack_id',
            label: 'Rack',
            kind: 'ref',
            options: racks,
            help: "A rack at the panel's site.",
          },
          {
            key: 'status',
            label: 'Status',
            kind: 'select',
            options: choices('feed_statuses'),
            initial: 'active',
          },
          {
            key: 'type',
            label: 'Type',
            kind: 'select',
            options: choices('feed_types'),
            initial: 'primary',
          },
          {
            key: 'supply',
            label: 'Supply',
            kind: 'select',
            options: choices('feed_supplies'),
            initial: 'ac',
          },
          {
            key: 'phase',
            label: 'Phase',
            kind: 'select',
            options: choices('feed_phases'),
            initial: 'single',
          },
          {
            key: 'voltage',
            label: 'Voltage (V)',
            kind: 'number',
            initial: 230,
            min: -1000,
            max: 1000,
            required: true,
          },
          {
            key: 'amperage',
            label: 'Amperage (A)',
            kind: 'number',
            initial: 16,
            min: 1,
            max: 10000,
            required: true,
          },
          {
            key: 'max_utilization',
            label: 'Maximum utilisation (%)',
            kind: 'number',
            initial: 80,
            min: 1,
            max: 100,
            required: true,
          },
          { key: 'description', label: 'Description', kind: 'text' },
        ]}
        columns={[
          { label: 'Panel', render: (r) => <Val value={r.power_panel_name} /> },
          { label: 'Name', render: (r) => String(r.name) },
          { label: 'Rack', render: (r) => <Val value={r.rack_name} /> },
          { label: 'Type', render: (r) => <Val value={r.type} /> },
          {
            label: 'Supply',
            render: (r) => `${String(r.voltage)} V · ${String(r.amperage)} A · ${String(r.phase)}`,
          },
          {
            label: 'Cable',
            render: (r) => <CableCell row={r} type="power_feed" />,
          },
        ]}
      />
      <HostFilter value={hostId} onChange={setHostId} hosts={hosts} />
      <RecordSection
        kind="power_port"
        title="Power ports"
        what="power port"
        filters={{ host_id: hostId }}
        emptyText="No power ports yet."
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
            key: 'maximum_draw',
            label: 'Maximum draw (W)',
            kind: 'number',
            min: 1,
          },
          {
            key: 'allocated_draw',
            label: 'Allocated draw (W)',
            kind: 'number',
            min: 1,
          },
          { key: 'description', label: 'Description', kind: 'text' },
        ]}
        columns={[
          { label: 'Device', render: (r) => <Val value={r.host_name} /> },
          { label: 'Name', render: (r) => String(r.name) },
          {
            label: 'Maximum',
            render: (r) => formatWatts(r.maximum_draw as number | null),
            align: 'right',
          },
          {
            label: 'Allocated',
            render: (r) => formatWatts(r.allocated_draw as number | null),
            align: 'right',
          },
          {
            label: 'Cable',
            render: (r) => <CableCell row={r} type="power_port" />,
          },
        ]}
      />
      <RecordSection
        kind="power_outlet"
        title="Power outlets"
        what="power outlet"
        filters={{ host_id: hostId }}
        emptyText="No power outlets yet. A PDU is a device with a power port feeding its outlets."
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
            key: 'power_port_id',
            label: 'Fed by power port',
            kind: 'ref',
            options: ports,
            help: 'A power port of the same device.',
          },
          {
            key: 'feed_leg',
            label: 'Feed leg',
            kind: 'select',
            options: choices('feed_legs'),
            initial: '',
          },
          { key: 'description', label: 'Description', kind: 'text' },
        ]}
        columns={[
          { label: 'Device', render: (r) => <Val value={r.host_name} /> },
          { label: 'Name', render: (r) => String(r.name) },
          { label: 'Fed by', render: (r) => <Val value={r.power_port_name} /> },
          { label: 'Leg', render: (r) => <Val value={r.feed_leg} /> },
          {
            label: 'Cable',
            render: (r) => <CableCell row={r} type="power_outlet" />,
          },
        ]}
      />
    </div>
  );
}
