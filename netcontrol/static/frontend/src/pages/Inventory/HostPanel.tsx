import { type ReactNode, useState } from 'react';
import { Link } from 'react-router';

import { useAuthStatus } from '@/api/auth';
import { useMonitoringPollHistory } from '@/api/deviceDetail';
import type { InventoryHost } from '@/api/inventory';
import { ChangelogPanel } from '@/components/ChangelogPanel';
import { QueryError } from '@/components/QueryError';
import { TabBar } from '@/components/TabBar';
import { TagChip, TagChips } from '@/components/TagChips';
import { WidenToggle } from '@/components/WidenToggle';
import { valueText } from '@/lib/customData';
import { hostModelText } from '@/lib/deviceModel';
import { canUseFeature } from '@/lib/tabGating';
import { DETAIL_STACK_STYLE } from '@/lib/wideDetail';
import { DeviceDcim } from '@/pages/Dcim/DeviceDcim';
import { DeviceCircuits } from '@/pages/Circuits/DeviceCircuits';
import { DeviceInfoBar } from '@/pages/DeviceDetail/DeviceInfoBar';
import { DeviceLifecycle } from '@/pages/Software/DeviceLifecycle';
import {
  HostAuditTab,
  HostConfigTab,
  HostErrorsTab,
  HostInterfacesTab,
  HostMacArpTab,
  HostVlansTab,
} from '@/pages/Topology/HostDataTabs';
import { isOpnsenseDevice } from '@/pages/Topology/opnsenseRules';
import { OpnsenseRulesTab } from '@/pages/Topology/OpnsenseRulesTab';
import { HostClusters } from '@/pages/Virtualization/HostClusters';

type TabKey = 'config' | 'rules' | 'interfaces' | 'vlans' | 'mac' | 'errors' | 'audit' | 'changelog';

/** The panel's tabs and the feature whose API each one reads (null: always shown). */
const TABS: { key: TabKey; label: string; feature: string | null }[] = [
  { key: 'config', label: 'Config', feature: 'config-backups' },
  { key: 'rules', label: 'Rules', feature: 'config-backups' },
  { key: 'interfaces', label: 'Interfaces', feature: 'reports' },
  { key: 'vlans', label: 'VLANs', feature: 'reports' },
  { key: 'mac', label: 'MAC/ARP', feature: 'mac-tracking' },
  { key: 'errors', label: 'Errors', feature: 'monitoring' },
  { key: 'audit', label: 'Audit', feature: 'reports' },
  { key: 'changelog', label: 'Changelog', feature: null },
];

interface Props {
  host: InventoryHost;
  groupName: string;
  canWrite: boolean;
  wide: boolean;
  onToggleWide: () => void;
  onEdit: () => void;
  onClose: () => void;
}

/**
 * The Inventory page's panel for one host: its record, its newest poll, what
 * other features know about it (cluster, rack and cables, lifecycle,
 * circuits) and tabs with its collected data and config backup, with links
 * to the device page and to the device on the Topology map.
 */
export function HostPanel({ host, groupName, canWrite, wide, onToggleWide, onEdit, onClose }: Props) {
  const auth = useAuthStatus().data;
  const canMonitor = canUseFeature('monitoring', auth);
  const canMap = canUseFeature('topology', auth);
  const tabs = TABS.filter(
    (t) => (t.feature === null || canUseFeature(t.feature, auth)) && (t.key !== 'rules' || isOpnsenseDevice(host.device_type)),
  );
  const [tab, setTab] = useState<TabKey>('config');
  const shown = tabs.some((t) => t.key === tab) ? tab : tabs[0].key;

  return (
    <div style={DETAIL_STACK_STYLE}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem' }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <h3 style={{ margin: 0, overflowWrap: 'anywhere' }}>{host.hostname}</h3>
          <div className="text-muted" style={{ fontSize: '0.9em' }}>
            {host.ip_address} · {groupName}
          </div>
        </div>
        <WidenToggle wide={wide} onToggle={onToggleWide} />
        <button type="button" className="modal-close" aria-label="Close host details" title="Close" onClick={onClose}>
          ×
        </button>
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)' }}>
        {canMonitor && (
          <Link className="btn btn-sm btn-secondary" to={`/devices/${host.id}`}>
            Open device page
          </Link>
        )}
        {canMap && (
          <Link className="btn btn-sm btn-secondary" to={`/topology?host=${host.id}`} title="Open the Topology map zoomed in on this device">
            Show on map
          </Link>
        )}
        <button type="button" className="btn btn-sm btn-secondary" onClick={onEdit} disabled={!canWrite}>
          Edit
        </button>
      </div>

      {canMonitor && <HostPoll hostId={host.id} />}

      <HostRecord host={host} />

      <HostClusters hostId={host.id} />
      <DeviceDcim hostId={host.id} />
      <DeviceLifecycle hostId={host.id} />
      <DeviceCircuits hostId={host.id} />

      <section aria-label="Collected data">
        <TabBar size="sm" aria-label="Host data" tabs={tabs.map((t) => ({ key: t.key, label: t.label }))} active={shown} onChange={setTab} />
        <div style={{ marginTop: '0.6rem', minWidth: 0 }}>
          {shown === 'config' && <HostConfigTab hostId={host.id} />}
          {shown === 'rules' && <OpnsenseRulesTab hostId={host.id} />}
          {shown === 'interfaces' && <HostInterfacesTab hostId={host.id} />}
          {shown === 'vlans' && <HostVlansTab hostId={host.id} />}
          {shown === 'mac' && <HostMacArpTab hostId={host.id} />}
          {shown === 'errors' && <HostErrorsTab hostId={host.id} />}
          {shown === 'audit' && <HostAuditTab hostId={host.id} />}
          {shown === 'changelog' && <ChangelogPanel objectType="host" objectId={host.id} title={null} pageSize={10} />}
        </div>
      </section>
    </div>
  );
}

function HostPoll({ hostId }: { hostId: number }) {
  const q = useMonitoringPollHistory(hostId, 1);
  if (q.isError && !q.data) return <QueryError what="the latest poll" query={q} />;
  if (q.isPending) return null;
  return <DeviceInfoBar poll={q.data.polls?.[0] ?? null} hostId={hostId} />;
}

/** The host's inventory record: what was entered or discovered for it. */
function HostRecord({ host }: { host: InventoryHost }) {
  const custom = Object.entries(host.custom_fields ?? {}).filter(([, v]) => valueText(v) !== '');
  const rows: [string, ReactNode][] = [
    ['Platform', host.device_type || 'cisco_ios'],
    ['Model', hostModelText(host)],
    ['Serial', host.serial_number],
    ['Software', host.software_version],
    ['Status', host.status],
    ['Site', host.site?.name],
    ['Location', host.location_detail],
    ['Tenant', host.tenant?.name],
    ['VRF', host.vrf_name],
    ['VLAN', host.vlan_id],
    ['AWS instance', host.aws_instance_id],
    [
      'Role',
      host.role && (
        <TagChip color={host.role.color} title="Role">
          {host.role.name}
        </TagChip>
      ),
    ],
    [
      'Lifecycle',
      host.lifecycle_status && (
        <TagChip color={host.lifecycle_status.color} title="Lifecycle status">
          {host.lifecycle_status.name}
        </TagChip>
      ),
    ],
    ['Tags', host.tags && host.tags.length > 0 && <TagChips tags={host.tags} />],
    ...custom.map(([key, value]): [string, ReactNode] => [key, valueText(value)]),
  ];
  const filled = rows.filter(([, v]) => v !== null && v !== undefined && v !== '' && v !== false && v !== '-');
  return (
    <section aria-label="Inventory record">
      <div style={{ fontWeight: 600, marginBottom: '0.45rem' }}>Inventory record</div>
      <dl style={{ display: 'grid', gridTemplateColumns: 'max-content minmax(0, 1fr)', gap: '0.3rem 1rem', margin: 0 }}>
        {filled.map(([label, value]) => (
          <div key={label} style={{ display: 'contents' }}>
            <dt className="text-muted">{label}</dt>
            <dd style={{ margin: 0, overflowWrap: 'anywhere' }}>{value}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
