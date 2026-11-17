import type { Webhook, WebhookPayload } from '@/api/webhooks';
import type { Tone } from '@/lib/severity';

/** Pure helpers for the Webhooks tab: the editor draft and its conversions. */

export interface HeaderRow {
  name: string;
  value: string;
}

export interface WebhookDraft {
  id: number | null;
  name: string;
  enabled: boolean;
  url: string;
  http_method: string;
  content_type: string;
  object_types: string[];
  actions: string[];
  /** Comma separated inventory group ids for the `group_id` filter. */
  group_ids: string;
  /** Filters other than group_id, kept as they came from the API. */
  other_filters: Record<string, (string | number)[]>;
  headers: HeaderRow[];
  secret: string;
  body_template: string;
  verify_tls: boolean;
  ca_bundle: string;
  timeout_seconds: number;
  max_retries: number;
  concurrency: number;
}

export const EMPTY_DRAFT: WebhookDraft = {
  id: null,
  name: '',
  enabled: true,
  url: '',
  http_method: 'POST',
  content_type: 'application/json',
  object_types: ['host'],
  actions: ['create', 'update', 'delete'],
  group_ids: '',
  other_filters: {},
  headers: [],
  secret: '',
  body_template: '',
  verify_tls: true,
  ca_bundle: '',
  timeout_seconds: 10,
  max_retries: 3,
  concurrency: 2,
};

/** "1, 2 3,,2" -> ["1", "2", "3"]: trimmed, de-duplicated, order kept. */
export function parseIdList(text: string): string[] {
  const out: string[] = [];
  for (const part of text.split(/[\s,]+/)) {
    const v = part.trim();
    if (v && !out.includes(v)) out.push(v);
  }
  return out;
}

export function draftFromWebhook(w: Webhook): WebhookDraft {
  const { group_id: groupIds = [], ...other } = w.filters ?? {};
  return {
    id: w.id,
    name: w.name,
    enabled: w.enabled,
    url: w.url,
    http_method: w.http_method,
    content_type: w.content_type,
    object_types: [...w.object_types],
    actions: [...w.actions],
    group_ids: groupIds.map(String).join(', '),
    other_filters: other,
    headers: Object.entries(w.headers ?? {}).map(([name, value]) => ({ name, value })),
    secret: w.secret,
    body_template: w.body_template,
    verify_tls: w.verify_tls,
    ca_bundle: w.ca_bundle,
    timeout_seconds: w.timeout_seconds,
    max_retries: w.max_retries,
    concurrency: w.concurrency,
  };
}

export function payloadFromDraft(d: WebhookDraft): WebhookPayload {
  const filters: Record<string, (string | number)[]> = { ...d.other_filters };
  const groups = parseIdList(d.group_ids);
  if (groups.length) filters.group_id = groups;
  const headers: Record<string, string> = {};
  for (const row of d.headers) {
    const name = row.name.trim();
    if (name) headers[name] = row.value;
  }
  return {
    name: d.name.trim(),
    enabled: d.enabled,
    url: d.url.trim(),
    http_method: d.http_method,
    content_type: d.content_type.trim(),
    object_types: d.object_types,
    actions: d.actions,
    filters,
    headers,
    secret: d.secret,
    body_template: d.body_template,
    verify_tls: d.verify_tls,
    ca_bundle: d.ca_bundle,
    timeout_seconds: d.timeout_seconds,
    max_retries: d.max_retries,
    concurrency: d.concurrency,
  };
}

/** Add or remove `value` from a list, keeping the order of `all`. */
export function toggleIn(list: string[], value: string, on: boolean, all: string[]): string[] {
  const set = new Set(list);
  if (on) set.add(value);
  else set.delete(value);
  return all.filter((v) => set.has(v));
}

export function deliveryTone(status: string): Tone {
  switch (status) {
    case 'success':
      return 'success';
    case 'retrying':
      return 'warning';
    case 'failed':
    case 'blocked':
      return 'danger';
    default:
      return 'neutral';
  }
}

export const OBJECT_TYPE_LABELS: Record<string, string> = {
  host: 'Hosts',
  group: 'Groups',
  prefix: 'IPAM prefixes',
  ip_address: 'IP addresses',
  vlan: 'VLANs',
  vrf: 'VRFs',
  credential: 'Credentials (metadata)',
  config_backup: 'Config backups',
  job: 'Jobs / playbook runs',
  circuit_provider: 'Circuit providers',
  provider_network: 'Provider networks',
  circuit_type: 'Circuit types',
  circuit: 'Circuits',
  circuit_termination: 'Circuit terminations',
  rack: 'Racks',
  rack_reservation: 'Rack reservations',
  front_port: 'Front ports',
  rear_port: 'Rear ports',
  module: 'Modules',
  power_panel: 'Power panels',
  power_feed: 'Power feeds',
  power_port: 'Power ports',
  power_outlet: 'Power outlets',
  cable: 'Cables',
  cluster_type: 'Cluster types',
  cluster_group: 'Cluster groups',
  cluster: 'Clusters',
  virtual_machine: 'Virtual machines',
  vm_interface: 'VM interfaces',
};
