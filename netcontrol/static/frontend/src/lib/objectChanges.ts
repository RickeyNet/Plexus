import type { ObjectChange } from '@/api/objectChanges';
import type { Tone } from '@/lib/severity';

/** One row of a change's field-by-field diff. */
export interface DiffRow {
  field: string;
  before: unknown;
  after: unknown;
  /** `added`: a create (no before); `removed`: a delete (no after). */
  kind: 'added' | 'removed' | 'changed';
}

// Row keys that say nothing about the change itself.
const HIDDEN_FIELDS = new Set(['id']);

const TYPE_LABELS: Record<string, string> = {
  host: 'Host',
  group: 'Inventory group',
  prefix: 'Prefix',
  ip_address: 'IP address',
  vlan: 'VLAN',
  vrf: 'VRF',
  credential: 'Credential',
  config_backup: 'Config backup',
  job: 'Job',
  region: 'Region',
  site: 'Site',
  tenant_group: 'Tenant group',
  tenant: 'Tenant',
  rack: 'Rack',
  rack_reservation: 'Rack reservation',
  front_port: 'Front port',
  rear_port: 'Rear port',
  module: 'Module',
  power_panel: 'Power panel',
  power_feed: 'Power feed',
  power_port: 'Power port',
  power_outlet: 'Power outlet',
  cable: 'Cable',
  cluster_type: 'Cluster type',
  cluster_group: 'Cluster group',
  cluster: 'Cluster',
  virtual_machine: 'Virtual machine',
  vm_interface: 'VM interface',
  circuit_provider: 'Circuit provider',
  provider_network: 'Provider network',
  circuit_type: 'Circuit type',
  circuit: 'Circuit',
  circuit_termination: 'Circuit termination',
  autonomous_system: 'Autonomous system',
  routing_instance: 'Routing instance',
  bgp_peer_group: 'BGP peer group',
  bgp_peering: 'BGP peering',
  hardware_notice: 'End-of-life notice',
  support_contract: 'Support contract',
};

/** Display name of a change log object type; unknown types pass through. */
export function objectTypeLabel(type: string): string {
  return TYPE_LABELS[type] ?? type;
}

/**
 * Features whose objects a non-admin may read the changes of (the API checks
 * each type against its feature; credentials are for admins only).
 */
export const CHANGE_LOG_FEATURES = ['inventory', 'ipam', 'config-backups', 'jobs', 'circuits', 'routing', 'virtualization', 'dcim', 'organization', 'lifecycle'];

/** The object types the change log tracks, for filter menus. */
export const OBJECT_TYPES = Object.keys(TYPE_LABELS);

const ACTION_TONES: Record<string, Tone> = { create: 'success', update: 'info', delete: 'danger' };

export function actionTone(action: string): Tone {
  return ACTION_TONES[action] ?? 'neutral';
}

export function actionLabel(action: string): string {
  return action ? action[0].toUpperCase() + action.slice(1) : '-';
}

function snapshotRows(snapshot: Record<string, unknown> | null, kind: 'added' | 'removed'): DiffRow[] {
  if (!snapshot) return [];
  return Object.keys(snapshot)
    .filter((field) => !HIDDEN_FIELDS.has(field))
    .filter((field) => snapshot[field] !== null && snapshot[field] !== undefined && snapshot[field] !== '')
    .sort()
    .map((field) =>
      kind === 'added'
        ? { field, before: null, after: snapshot[field], kind }
        : { field, before: snapshot[field], after: null, kind },
    );
}

/**
 * The field-by-field diff of one change: the changed fields of an update,
 * every set field of a created object (before empty) or of a deleted one
 * (after empty). Sorted by field name.
 */
export function diffRows(change: Pick<ObjectChange, 'action' | 'changes' | 'before' | 'after'>): DiffRow[] {
  if (change.action === 'create') return snapshotRows(change.after, 'added');
  if (change.action === 'delete') return snapshotRows(change.before, 'removed');
  return Object.keys(change.changes ?? {})
    .sort()
    .map((field) => ({
      field,
      before: change.changes[field]?.before ?? null,
      after: change.changes[field]?.after ?? null,
      kind: 'changed' as const,
    }));
}

/** A diff value as text: "-" for nothing, JSON for lists and objects. */
export function formatChangeValue(value: unknown): string {
  if (value === null || value === undefined || value === '') return '-';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return JSON.stringify(value);
}
