import { useMemo, useState } from 'react';

import { useAuthStatus } from '@/api/auth';
import { type DcimRecord, useDcimRecord } from '@/api/dcim';
import { useRegions } from '@/api/organization';
import { Badge } from '@/components/Badge';
import { DataTable } from '@/components/DataTable';
import { LoadingState } from '@/components/LoadingState';
import { ProgressBar } from '@/components/ProgressBar';
import { QueryError } from '@/components/QueryError';
import { aggregateUsageLabel, GLOBAL_NAMESPACE_ID, vidRangeLabel, vlanGroupScope } from '@/lib/ipamModel';
import { utilizationTone } from '@/lib/severity';

import { useRecordOptions, useSiteOptions } from '../Dcim/hooks';
import { RecordSection, Val } from '../Dcim/RecordSection';
import { DetailSection, SplitLayout } from './NetworkObjectParts';

/**
 * The IPAM page's Namespaces, Route targets, VLAN groups and Aggregates tabs:
 * catalogue records on the shared record section (read with IPAM access,
 * changed by admins).
 */

const RIGHT = 'right' as const;
const count = (value: unknown) => Number(value ?? 0).toLocaleString();

function useIsAdmin(): boolean {
  return useAuthStatus().data?.role === 'admin';
}

const DESCRIPTION = { key: 'description', label: 'Description', kind: 'text' } as const;

/** Namespaces: groups of VRFs and prefixes in which address space may repeat. */
export function NamespacesTab() {
  return (
    <RecordSection
      kind="namespace"
      title="Namespaces"
      what="namespace"
      canWrite={useIsAdmin()}
      emptyText="No namespaces yet."
      fields={[{ key: 'name', label: 'Name', kind: 'text', required: true }, DESCRIPTION]}
      columns={[
        {
          label: 'Name',
          render: (r) => (
            <>
              {String(r.name)}{' '}
              {r.id === GLOBAL_NAMESPACE_ID && (
                <Badge size="sm" title="Every VRF and prefix is here unless moved; it cannot be deleted">
                  Default
                </Badge>
              )}
            </>
          ),
        },
        { label: 'VRFs', render: (r) => count(r.vrf_count), align: RIGHT },
        { label: 'Prefixes', render: (r) => count(r.prefix_count), align: RIGHT },
        { label: 'Description', render: (r) => <Val value={r.description} /> },
      ]}
    />
  );
}

/** Route targets: the BGP extended communities VRFs import and export. */
export function RouteTargetsTab() {
  return (
    <RecordSection
      kind="route_target"
      title="Route targets"
      what="route target"
      canWrite={useIsAdmin()}
      emptyText="No route targets yet."
      fields={[
        {
          key: 'name',
          label: 'Route target',
          kind: 'text',
          required: true,
          help: 'ASN:number (65000:100) or IPv4:number (192.0.2.1:100).',
        },
        { key: 'tenant_id', label: 'Tenant', kind: 'tenant' },
        DESCRIPTION,
      ]}
      columns={[
        { label: 'Route target', render: (r) => String(r.name) },
        { label: 'Imported by', render: (r) => `${count(r.import_vrf_count)} VRFs`, align: RIGHT },
        { label: 'Exported by', render: (r) => `${count(r.export_vrf_count)} VRFs`, align: RIGHT },
        { label: 'Tenant', render: (r) => <Val value={r.tenant_name} /> },
        { label: 'Description', render: (r) => <Val value={r.description} /> },
      ]}
    />
  );
}

interface VlanGroupDetail extends DcimRecord {
  vlans: { id: number; vid: number; name: string; site_id: number | null }[];
  available: number;
  next_vid: number | null;
}

function VlanGroupPanel({ id }: { id: number | null }) {
  const q = useDcimRecord<VlanGroupDetail>('vlan_group', id);
  if (id === null) {
    return (
      <>
        <h3 style={{ margin: '0 0 0.75rem' }}>VLAN group details</h3>
        <p className="text-muted" style={{ margin: 0 }}>
          Select a VLAN group to see its VLANs and the next free VLAN id.
        </p>
      </>
    );
  }
  if (q.isError && !q.data) return <QueryError what="VLAN group details" query={q} />;
  if (q.isPending) return <LoadingState text="Loading VLAN group details…" />;
  const g = q.data;
  return (
    <div className="stack stack-sm">
      <div>
        <h3 style={{ margin: 0 }}>VLAN group {String(g.name)}</h3>
        <div className="text-muted" style={{ fontSize: '0.9em' }}>
          VLAN ids {vidRangeLabel(g)} · {vlanGroupScope(g)} · {g.available.toLocaleString()} free
        </div>
      </div>
      <div>
        <strong>Next free VLAN id:</strong> {g.next_vid ?? 'none, the group is full'}
      </div>
      <DetailSection title="VLANs" count={g.vlans.length} empty="No VLAN is in this group.">
        <DataTable compact aria-label={`VLANs in group ${String(g.name)}`} maxHeight={320}>
          <thead>
            <tr>
              <th>VLAN</th>
              <th>Name</th>
            </tr>
          </thead>
          <tbody>
            {g.vlans.map((v) => (
              <tr key={v.id}>
                <td>{v.vid}</td>
                <td>{v.name || <span className="text-muted">-</span>}</td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      </DetailSection>
    </div>
  );
}

/** VLAN groups: pools of VLAN ids, each id once per group, optionally scoped to a site or region. */
export function VlanGroupsTab() {
  const sites = useSiteOptions();
  const regionsQ = useRegions();
  const regions = useMemo(() => (regionsQ.data ?? []).map((r) => ({ value: r.id, label: r.name })), [regionsQ.data]);
  const [selected, setSelected] = useState<number | null>(null);
  const list = (
    <RecordSection
      kind="vlan_group"
      title="VLAN groups"
      what="VLAN group"
      canWrite={useIsAdmin()}
      emptyText="No VLAN groups yet."
      onSelect={(r) => setSelected(r.id)}
      selectedId={selected}
      fields={[
        { key: 'name', label: 'Name', kind: 'text', required: true },
        { key: 'min_vid', label: 'Lowest VLAN id', kind: 'number', initial: 1, min: 1, max: 4094, required: true },
        { key: 'max_vid', label: 'Highest VLAN id', kind: 'number', initial: 4094, min: 1, max: 4094, required: true },
        { key: 'site_id', label: 'Site', kind: 'ref', options: sites, help: 'Only VLANs of this site (or of no site) may join.' },
        { key: 'region_id', label: 'Region', kind: 'ref', options: regions, help: 'Or only VLANs of sites in this region.' },
        DESCRIPTION,
      ]}
      columns={[
        { label: 'Name', render: (r) => String(r.name) },
        { label: 'VLAN ids', render: (r) => vidRangeLabel(r) },
        { label: 'Scope', render: (r) => vlanGroupScope(r) },
        { label: 'VLANs', render: (r) => count(r.vlan_count), align: RIGHT },
        { label: 'Description', render: (r) => <Val value={r.description} /> },
      ]}
    />
  );
  return <SplitLayout list={list} detail={<VlanGroupPanel id={selected} />} />;
}

/** RIRs and the aggregates they allocated, with how much of each the prefixes cover. */
export function AggregatesTab() {
  const isAdmin = useIsAdmin();
  const rirs = useRecordOptions('rir', (r) => String(r.name));
  return (
    <div>
      <RecordSection
        kind="aggregate"
        title="Aggregates"
        what="aggregate"
        canWrite={isAdmin}
        nameOf={(r) => String(r.prefix)}
        emptyText="No aggregates yet. Add a RIR first, then the blocks it allocated."
        fields={[
          { key: 'prefix', label: 'Prefix', kind: 'text', required: true, help: 'A network in CIDR form, such as 198.51.100.0/24.' },
          { key: 'rir_id', label: 'RIR', kind: 'ref', options: rirs, required: true },
          { key: 'date_added', label: 'Date added', kind: 'text', help: 'YYYY-MM-DD.' },
          { key: 'tenant_id', label: 'Tenant', kind: 'tenant' },
          DESCRIPTION,
        ]}
        columns={[
          { label: 'Prefix', render: (r) => String(r.prefix) },
          { label: 'RIR', render: (r) => <Val value={r.rir_name} /> },
          { label: 'Prefixes', render: (r) => count(r.prefix_count), align: RIGHT },
          {
            label: 'Utilization',
            render: (r) => (
              <div title={aggregateUsageLabel(r)} style={{ minWidth: '8rem' }}>
                <ProgressBar
                  size="sm"
                  value={Number(r.utilization_pct ?? 0)}
                  tone={utilizationTone(Number(r.utilization_pct ?? 0))}
                  label={`Utilization of ${String(r.prefix)}`}
                />
                <span style={{ fontSize: '0.85em' }}>{aggregateUsageLabel(r)}</span>
              </div>
            ),
          },
          { label: 'Date added', render: (r) => <Val value={r.date_added} /> },
          { label: 'Tenant', render: (r) => <Val value={r.tenant_name} /> },
        ]}
      />
      <RecordSection
        kind="rir"
        title="RIRs"
        what="RIR"
        canWrite={isAdmin}
        emptyText="No RIRs yet."
        fields={[
          { key: 'name', label: 'Name', kind: 'text', required: true, help: 'A registry such as ARIN or RIPE NCC, or a private allocator.' },
          { key: 'is_private', label: 'Private (RFC 1918, RFC 6598, documentation...)', kind: 'checkbox' },
          DESCRIPTION,
        ]}
        columns={[
          { label: 'Name', render: (r) => String(r.name) },
          { label: 'Private', render: (r) => (r.is_private ? 'Yes' : 'No') },
          { label: 'Aggregates', render: (r) => count(r.aggregate_count), align: RIGHT },
          { label: 'Description', render: (r) => <Val value={r.description} /> },
        ]}
      />
    </div>
  );
}
