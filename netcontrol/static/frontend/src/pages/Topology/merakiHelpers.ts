import type {
  CatoBuildOptions,
  DetailSection,
  MerakiBuildJob,
  MerakiBuildOptions,
  MerakiNodeDetails,
} from '@/api/meraki';

export const DEFAULT_BASE_URL = 'https://api.meraki.com/api/v1';

export const FALLBACK_OPTIONS: MerakiBuildOptions = {
  network_tags: [],
  network_name_contains: '',
  include_lldp_cdp: true,
  include_switch_ports: true,
  include_port_statuses: false,
  include_switch_routing: true,
  include_firewall: true,
  include_wireless: true,
  include_clients: true,
  inventory_enrich: true,
  ssh_enrich: false,
  max_concurrency: 5,
  requests_per_second: 8,
};

export const CATO_BASE_URL = 'https://api.catonetworks.com/api/v1/graphql2';

export const FALLBACK_CATO_OPTIONS: CatoBuildOptions = {
  site_name_contains: '',
  include_users: true,
  include_ranges: true,
  inventory_enrich: true,
};

type CatoToggleKey = {
  [K in keyof CatoBuildOptions]: CatoBuildOptions[K] extends boolean ? K : never;
}[keyof CatoBuildOptions];

export const CATO_OPTION_TOGGLES: { key: CatoToggleKey; label: string; hint: string }[] = [
  { key: 'include_users', label: 'Remote users', hint: 'Users connected with the Cato Client when the collection runs: name, device, VPN IP, public IP and PoP. Shown as one node.' },
  { key: 'include_ranges', label: 'Network ranges (subnets)', hint: 'The ranges behind every site, for search and for picking path endpoints by subnet.' },
  { key: 'inventory_enrich', label: 'Correlate with Plexus inventory', hint: 'Attach SNMP/SSH data Plexus already holds for a Socket that is also an inventory host.' },
];

type ToggleKey = {
  [K in keyof MerakiBuildOptions]: MerakiBuildOptions[K] extends boolean ? K : never;
}[keyof MerakiBuildOptions];

export const OPTION_TOGGLES: { key: ToggleKey; label: string; hint: string }[] = [
  { key: 'include_lldp_cdp', label: 'LLDP / CDP neighbors', hint: 'Per-device neighbor tables; finds non-Meraki gear. One API call per device.' },
  { key: 'include_switch_ports', label: 'Switch port configuration', hint: 'VLAN, trunk, PoE and STP settings for every switch port.' },
  { key: 'include_port_statuses', label: 'Live switch port status', hint: 'Link speed, duplex, clients and errors. One extra API call per switch.' },
  { key: 'include_switch_routing', label: 'Switch routing (SVIs, static routes, OSPF)', hint: 'Layer 3 interfaces and routes on switches and stacks.' },
  { key: 'include_firewall', label: 'Firewall and NAT rules', hint: 'Layer 3 firewall, port forwarding and 1:1 NAT per appliance network.' },
  { key: 'include_wireless', label: 'Wireless SSIDs', hint: 'Enabled SSIDs with auth mode and VLAN. Pre-shared keys are never collected.' },
  { key: 'include_clients', label: 'Clients (MAC / IP)', hint: 'Clients seen in the last day with MAC, IP, VLAN and port - the MAC/ARP tab. One paginated API call per network.' },
  { key: 'inventory_enrich', label: 'Correlate with Plexus inventory', hint: 'Attach SNMP/SSH data Plexus already holds for matching devices and neighbors.' },
  { key: 'ssh_enrich', label: 'Live SSH show commands', hint: 'SSH to matched inventory hosts with the Plexus service credential for routes, VLANs and neighbors.' },
];

export function formatWhen(iso?: string | null): string {
  if (!iso) return '-';
  const normalized = /[zZ]|[+-]\d\d:?\d\d$/.test(iso) ? iso : `${iso.replace(' ', 'T')}Z`;
  const date = new Date(normalized);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString();
}

export function buildStatusBadge(status?: string): string {
  if (status === 'success') return 'badge badge-success';
  if (status === 'partial') return 'badge badge-warning';
  if (status === 'failed') return 'badge badge-danger';
  return 'badge';
}

const PHASE_LABELS: Record<string, string> = {
  starting: 'Starting',
  inventory: 'Reading organization inventory',
  organization: 'Collecting organization-wide status',
  networks: 'Collecting network configuration',
  devices: 'Collecting device details',
  stacks: 'Collecting switch stack routing',
  collected: 'Collection finished',
  'cato sites': 'Reading Cato sites and Sockets',
  'cato users': 'Reading connected remote users',
  'cato ranges': 'Reading site network ranges',
  'building map': 'Building the map',
  saving: 'Saving snapshot',
};

export function describeProgress(job: MerakiBuildJob | undefined): { label: string; percent: number | null } {
  const progress = job?.progress ?? {};
  const phase = progress.phase ?? 'starting';
  if (phase === 'inventory' && progress.hosts_total) {
    return {
      label: `Enriching from Plexus inventory (${progress.hosts_done ?? 0} of ${progress.hosts_total} hosts)`,
      percent: Math.round(((progress.hosts_done ?? 0) / progress.hosts_total) * 100),
    };
  }
  const label = PHASE_LABELS[phase] ?? phase;
  if (progress.calls_total) {
    const done = progress.calls_done ?? 0;
    return {
      label: `${label} (${done} of ${progress.calls_total} API calls)`,
      percent: Math.min(100, Math.round((done / progress.calls_total) * 100)),
    };
  }
  return { label, percent: null };
}

/** A tab of the node details panel filled from Meraki Dashboard data. */
export type MerakiView =
  | 'meraki'
  | 'interfaces'
  | 'vlans'
  | 'mac'
  | 'routing'
  | 'vpn'
  | 'firewall'
  | 'switching'
  | 'wireless';

// Which collected sections (by title) each tab shows. 'meraki' is the device
// summary and takes every section no other tab claims, so nothing is lost
// when the collector gains a section.
const VIEW_TITLES: Record<Exclude<MerakiView, 'meraki'>, string[]> = {
  interfaces: [
    'Switch ports',
    'Appliance ports',
    'WAN uplinks',
    'Layer 3 interfaces (SVIs)',
    'Neighbors (LLDP/CDP)',
    'WAN links',
    'Site interfaces',
    'Network interfaces',
  ],
  vlans: ['VLANs', 'Single LAN', 'VLANs on ports', 'Layer 3 interfaces (SVIs)', 'Network ranges', 'Subnets'],
  mac: ['Clients (MAC/ARP)', 'Network clients (MAC/ARP)'],
  routing: [
    'Effective routes (derived)',
    'Static routes',
    'BGP',
    'BGP neighbors',
    'OSPF',
    'OSPF areas',
    'Route tables',
    'Transit gateway routes',
  ],
  vpn: ['Site-to-site VPN', 'VPN peers', 'VPN local subnets', 'IPsec tunnel', 'VPN connections'],
  firewall: ['Layer 3 firewall rules', 'Port forwarding', '1:1 NAT', 'Security group rules', 'Network ACL rules'],
  switching: ['Switch stacks', 'Spanning tree', 'STP bridge priority'],
  wireless: ['Wireless SSIDs'],
};

const CLAIMED_TITLES = new Set(Object.values(VIEW_TITLES).flat());

export const MERAKI_VIEW_ORDER: MerakiView[] = [
  'meraki',
  'interfaces',
  'vlans',
  'mac',
  'routing',
  'vpn',
  'firewall',
  'switching',
  'wireless',
];

function pickSections(sections: DetailSection[], view: MerakiView): DetailSection[] {
  if (view === 'meraki') return sections.filter((s) => !CLAIMED_TITLES.has(s.title));
  const titles = VIEW_TITLES[view];
  return sections.filter((s) => titles.includes(s.title));
}

/** The device's and its site's sections that belong on one tab. */
export function merakiViewSections(
  data: MerakiNodeDetails,
  view: MerakiView,
): { sections: DetailSection[]; siteSections: DetailSection[] } {
  // An appliance carries its whole site's configuration; any other device
  // still shows the site's VLANs on its VLANs tab.
  const site = data.site_sections.length ? data.site_sections : (data.site_addressing ?? []);
  return { sections: pickSections(data.sections, view), siteSections: pickSections(site, view) };
}

/** Tabs that have something to show for this device, in display order. */
export function merakiViewsWithData(data: MerakiNodeDetails): MerakiView[] {
  return MERAKI_VIEW_ORDER.filter((view) => {
    const { sections, siteSections } = merakiViewSections(data, view);
    return sections.length > 0 || siteSections.length > 0;
  });
}

export function searchTerms(text: string): string[] {
  return text.trim().toLowerCase().split(/\s+/).filter(Boolean);
}

export function rowMatches(cells: string[], terms: string[]): boolean {
  if (!terms.length) return false;
  const text = cells.join(' ').toLowerCase();
  return terms.every((t) => text.includes(t));
}

/** True when a row (or the text) of any section matches every term. */
export function sectionsMatch(sections: DetailSection[], terms: string[]): boolean {
  if (!terms.length) return false;
  return sections.some((s) =>
    s.kind === 'text' ? rowMatches([s.text ?? ''], terms) : (s.rows ?? []).some((r) => rowMatches(r, terms)),
  );
}
