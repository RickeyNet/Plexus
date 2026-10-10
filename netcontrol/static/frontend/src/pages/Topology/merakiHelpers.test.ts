import { describe, expect, it } from 'vitest';

import type { DetailSection, MerakiBuildJob, MerakiNodeDetails } from '@/api/meraki';

import {
  FALLBACK_FMC_OPTIONS,
  FMC_OPTION_TOGGLES,
  FALLBACK_PANORAMA_OPTIONS,
  PANORAMA_OPTION_TOGGLES,
  describeProgress,
  merakiViewSections,
  merakiViewsWithData,
  searchTerms,
  sectionsMatch,
  sourceTypeLabel,
} from './merakiHelpers';

function table(title: string, rows: string[][] = [['a']]): DetailSection {
  return { title, kind: 'table', columns: ['c'], rows };
}

function details(part: Partial<MerakiNodeDetails>): MerakiNodeDetails {
  return { sections: [], site_sections: [], site_addressing: [], ...part } as MerakiNodeDetails;
}

describe('meraki detail tabs', () => {
  it('offers only the tabs that have data, in display order', () => {
    const ap = details({
      sections: [table('Overview'), table('Neighbors (LLDP/CDP)'), table('Clients (MAC/ARP)')],
      site_addressing: [table('VLANs')],
    });
    expect(merakiViewsWithData(ap)).toEqual(['meraki', 'interfaces', 'vlans', 'mac']);
  });

  it('spreads an appliance and its site configuration over the category tabs', () => {
    const mx = details({
      sections: [table('Overview'), table('WAN uplinks')],
      site_sections: [
        table('Site overview'),
        table('VLANs'),
        table('Effective routes (derived)'),
        table('VPN peers'),
        table('Layer 3 firewall rules'),
        table('Wireless SSIDs'),
      ],
      site_addressing: [table('VLANs')],
    });
    expect(merakiViewsWithData(mx)).toEqual([
      'meraki',
      'interfaces',
      'vlans',
      'routing',
      'vpn',
      'firewall',
      'wireless',
    ]);
    // The site's VLANs are listed once, not again from site_addressing.
    expect(merakiViewSections(mx, 'vlans').siteSections.map((s) => s.title)).toEqual(['VLANs']);
  });

  it('keeps sections no tab claims on the device tab', () => {
    const node = details({ sections: [table('Something new'), table('Switch ports')] });
    expect(merakiViewSections(node, 'meraki').sections.map((s) => s.title)).toEqual(['Something new']);
  });

  it('finds the sections matching the map search', () => {
    const sections = [table('VLANs', [['10', 'Data', '10.0.10.0/24']])];
    expect(sectionsMatch(sections, searchTerms(' data 10.0.10 '))).toBe(true);
    expect(sectionsMatch(sections, searchTerms('voice'))).toBe(false);
    expect(sectionsMatch(sections, [])).toBe(false);
  });
});

describe('cato detail tabs', () => {
  it('files Socket and site sections under the shared tabs', () => {
    const socket = details({
      sections: [table('Overview'), table('WAN links')],
      site_sections: [table('Site overview'), table('Network ranges'), table('Site interfaces'), table('IPsec tunnel')],
    });
    expect(merakiViewsWithData(socket)).toEqual(['meraki', 'interfaces', 'vlans', 'vpn']);
    expect(merakiViewSections(socket, 'vlans').siteSections.map((s) => s.title)).toEqual(['Network ranges']);
    expect(merakiViewSections(socket, 'interfaces').sections.map((s) => s.title)).toEqual(['WAN links']);
  });
});

describe('fmc detail tabs', () => {
  it('files remote access VPN headend and policy sections under the shared tabs', () => {
    const ftd = details({
      sections: [table('Overview'), table('FTD interfaces')],
      site_sections: [
        table('Remote access VPN'),
        table('Connection profiles'),
        table('VPN address pools'),
        table('Access interfaces'),
      ],
    });
    expect(merakiViewsWithData(ftd)).toEqual(['meraki', 'interfaces', 'vlans', 'vpn']);
    expect(merakiViewSections(ftd, 'vlans').siteSections.map((s) => s.title)).toEqual(['VPN address pools']);
    expect(merakiViewSections(ftd, 'vpn').siteSections.map((s) => s.title)).toEqual([
      'Remote access VPN',
      'Connection profiles',
      'Access interfaces',
    ]);
    // Every other device of the site sees the pools too.
    const users = details({ sections: [table('Remote access users'), table('Connected users')], site_addressing: [table('VPN address pools')] });
    expect(merakiViewsWithData(users)).toEqual(['meraki', 'vlans', 'vpn']);
  });

  it('files an FTD with routing, NAT, access control and site-to-site VPN under every tab', () => {
    const ftd = details({
      sections: [
        table('Overview'),
        table('FTD interfaces'),
        table('Connected subnets'),
        table('Static routes'),
        table('Virtual routers'),
        table('BGP'),
        table('BGP neighbors'),
        table('OSPF'),
        table('OSPF areas'),
        table('EIGRP'),
        table('Policy-based routes'),
        table('ECMP zones'),
        table('NAT rules'),
        table('Access control'),
        table('Access control rules'),
        { title: 'Access control rules (note)', kind: 'text', text: 'Showing the first 1000 of 1500 rules' },
        table('Site-to-site VPN'),
        table('Health alerts'),
        table('Plexus inventory'),
      ],
    });
    expect(merakiViewsWithData(ftd)).toEqual(['meraki', 'interfaces', 'vlans', 'routing', 'vpn', 'firewall']);
    expect(merakiViewSections(ftd, 'vlans').sections.map((s) => s.title)).toEqual(['Connected subnets']);
    expect(merakiViewSections(ftd, 'routing').sections.map((s) => s.title)).toEqual([
      'Static routes',
      'Virtual routers',
      'BGP',
      'BGP neighbors',
      'OSPF',
      'OSPF areas',
      'EIGRP',
      'Policy-based routes',
      'ECMP zones',
    ]);
    expect(merakiViewSections(ftd, 'firewall').sections.map((s) => s.title)).toEqual([
      'NAT rules',
      'Access control',
      'Access control rules',
      'Access control rules (note)',
    ]);
    expect(merakiViewSections(ftd, 'vpn').sections.map((s) => s.title)).toEqual(['Site-to-site VPN']);
    // Health alerts have no tab of their own; they stay on the summary.
    expect(merakiViewSections(ftd, 'meraki').sections.map((s) => s.title)).toEqual([
      'Overview',
      'Health alerts',
      'Plexus inventory',
    ]);
  });
});

describe('fmc collection options', () => {
  it('offers a toggle for every boolean option, in the documented order', () => {
    expect(FMC_OPTION_TOGGLES.map((t) => t.label)).toEqual([
      'Every managed device',
      'Device interfaces',
      'Routing',
      'Site-to-site VPN',
      'NAT',
      'Access control policies',
      'Health',
      'Connected users',
      'Correlate with Plexus inventory',
      'Verify the FMC certificate',
    ]);
    const booleans = Object.entries(FALLBACK_FMC_OPTIONS)
      .filter(([, value]) => typeof value === 'boolean')
      .map(([key]) => key)
      .sort();
    expect(FMC_OPTION_TOGGLES.map((t) => t.key).sort()).toEqual(booleans);
    expect(FMC_OPTION_TOGGLES.every((t) => t.hint.length > 0)).toBe(true);
  });

  it('collects everything by default', () => {
    expect(FMC_OPTION_TOGGLES.every((t) => FALLBACK_FMC_OPTIONS[t.key])).toBe(true);
  });
});

describe('fmc progress', () => {
  const at = (phase: string) => describeProgress({ progress: { phase } } as MerakiBuildJob).label;

  it('names every phase of an FMC collection', () => {
    expect(
      [
        'fmc login',
        'fmc devices',
        'fmc ha',
        'fmc objects',
        'fmc vpn policies',
        'fmc pools',
        'fmc interfaces',
        'fmc routing',
        'fmc nat',
        'fmc access policies',
        'fmc s2s vpn',
        'fmc health',
        'fmc sessions',
        'collected',
      ].map(at),
    ).toEqual([
      'Signing in to the FMC',
      'Reading managed devices',
      'Reading HA pairs and clusters',
      'Reading network objects and zones',
      'Reading remote access VPN policies',
      'Reading VPN address pools',
      'Reading device interfaces',
      'Reading routing',
      'Reading NAT policies',
      'Reading access control policies',
      'Reading site-to-site VPN',
      'Reading health and deployment status',
      'Reading connected users',
      'Collection finished',
    ]);
  });

  it('counts API calls when the collector reports them', () => {
    const job = { progress: { phase: 'fmc routing', calls_done: 30, calls_total: 120 } } as MerakiBuildJob;
    expect(describeProgress(job)).toEqual({ label: 'Reading routing (30 of 120 API calls)', percent: 25 });
  });
});

describe('panorama detail tabs', () => {
  it('files a firewall with interfaces, routing, VPN, GlobalProtect and policy under every tab', () => {
    const fw = details({
      sections: [
        table('Overview'),
        table('Firewall interfaces'),
        table('Zones'),
        table('Connected subnets'),
        table('Virtual routers'),
        table('Static routes'),
        table('BGP'),
        table('OSPF'),
        table('Routing table'),
        table('BGP peers'),
        table('IKE gateways'),
        table('IPsec tunnels'),
        table('GlobalProtect gateways'),
        table('VPN address pools'),
        table('Connected users'),
        table('Security policy'),
        table('Security rules'),
        table('NAT rules'),
        table('Plexus inventory'),
      ],
    });
    expect(merakiViewsWithData(fw)).toEqual(['meraki', 'interfaces', 'vlans', 'routing', 'vpn', 'firewall']);
    expect(merakiViewSections(fw, 'interfaces').sections.map((s) => s.title)).toEqual(['Firewall interfaces', 'Zones']);
    expect(merakiViewSections(fw, 'vlans').sections.map((s) => s.title)).toEqual(['Connected subnets', 'VPN address pools']);
    expect(merakiViewSections(fw, 'routing').sections.map((s) => s.title)).toEqual([
      'Virtual routers',
      'Static routes',
      'BGP',
      'OSPF',
      'Routing table',
      'BGP peers',
    ]);
    expect(merakiViewSections(fw, 'vpn').sections.map((s) => s.title)).toEqual([
      'IKE gateways',
      'IPsec tunnels',
      'GlobalProtect gateways',
      'Connected users',
    ]);
    expect(merakiViewSections(fw, 'firewall').sections.map((s) => s.title)).toEqual([
      'Security policy',
      'Security rules',
      'NAT rules',
    ]);
    expect(merakiViewSections(fw, 'meraki').sections.map((s) => s.title)).toEqual(['Overview', 'Plexus inventory']);
  });
});

describe('panorama collection options', () => {
  it('offers a toggle for every boolean option, in the documented order', () => {
    expect(PANORAMA_OPTION_TOGGLES.map((t) => t.label)).toEqual([
      'Interfaces',
      'Routing',
      'Security policies',
      'NAT',
      'Site-to-site VPN',
      'GlobalProtect',
      'Device state',
      'Correlate with Plexus inventory',
      'Verify the Panorama certificate',
    ]);
    const booleans = Object.entries(FALLBACK_PANORAMA_OPTIONS)
      .filter(([, value]) => typeof value === 'boolean')
      .map(([key]) => key)
      .sort();
    expect(PANORAMA_OPTION_TOGGLES.map((t) => t.key).sort()).toEqual(booleans);
    expect(PANORAMA_OPTION_TOGGLES.every((t) => t.hint.length > 0)).toBe(true);
  });

  it('collects everything by default and signs in with an API key', () => {
    expect(PANORAMA_OPTION_TOGGLES.every((t) => FALLBACK_PANORAMA_OPTIONS[t.key])).toBe(true);
    expect(FALLBACK_PANORAMA_OPTIONS.username).toBe('');
  });
});

describe('panorama progress', () => {
  const at = (phase: string) => describeProgress({ progress: { phase } } as MerakiBuildJob).label;

  it('names every phase of a Panorama collection', () => {
    expect(
      [
        'panorama login',
        'panorama devices',
        'panorama device groups',
        'panorama templates',
        'panorama objects',
        'panorama policies',
        'panorama nat',
        'panorama network',
        'panorama vpn',
        'panorama global protect',
        'panorama device state',
      ].map(at),
    ).toEqual([
      'Signing in to Panorama',
      'Reading managed firewalls',
      'Reading device groups',
      'Reading templates and template stacks',
      'Reading address and service objects',
      'Reading security rules',
      'Reading NAT rules',
      'Reading interfaces and routing',
      'Reading IKE gateways and IPsec tunnels',
      'Reading GlobalProtect gateways and users',
      'Reading firewall state',
    ]);
  });
});

describe('aws detail tabs', () => {
  it('files VPC sections under the shared tabs', () => {
    const vpc = details({
      sections: [table('Overview')],
      site_sections: [
        table('VPC overview'),
        table('Subnets'),
        table('Route tables'),
        table('Instances'),
        table('Security group rules'),
      ],
    });
    expect(merakiViewsWithData(vpc)).toEqual(['meraki', 'vlans', 'routing', 'firewall']);
    expect(merakiViewSections(vpc, 'vlans').siteSections.map((s) => s.title)).toEqual(['Subnets']);
    // Instances have no tab of their own; they stay on the summary.
    expect(merakiViewSections(vpc, 'meraki').siteSections.map((s) => s.title)).toEqual(['VPC overview', 'Instances']);
  });
});

describe('azure detail tabs', () => {
  it('files VNet sections under the shared tabs', () => {
    const vnet = details({
      sections: [table('Overview'), table('VNet peerings')],
      site_sections: [
        table('VNet overview'),
        table('Subnets'),
        table('Route tables'),
        table('Virtual machines'),
        table('Network security group rules'),
      ],
    });
    expect(merakiViewsWithData(vnet)).toEqual(['meraki', 'vlans', 'routing', 'firewall']);
    expect(merakiViewSections(vnet, 'firewall').siteSections.map((s) => s.title)).toEqual(['Network security group rules']);
    expect(merakiViewSections(vnet, 'routing').sections.map((s) => s.title)).toEqual(['VNet peerings']);
  });
});

describe('gcp detail tabs', () => {
  it('files VPC network sections under the shared tabs', () => {
    const vpc = details({
      site_sections: [
        table('VPC network overview'),
        table('Subnets'),
        table('VPC routes'),
        table('Dynamic routes'),
        table('VPC peerings'),
        table('VM instances'),
        table('VPC firewall rules'),
      ],
    });
    expect(merakiViewsWithData(vpc)).toEqual(['meraki', 'vlans', 'routing', 'firewall']);
    expect(merakiViewSections(vpc, 'firewall').siteSections.map((s) => s.title)).toEqual(['VPC firewall rules']);
    expect(merakiViewSections(vpc, 'routing').siteSections.map((s) => s.title)).toEqual([
      'VPC routes',
      'Dynamic routes',
      'VPC peerings',
    ]);
    expect(merakiViewSections(vpc, 'vlans').siteSections.map((s) => s.title)).toEqual(['Subnets']);
    // VM instances have no tab of their own; they stay on the summary.
    expect(merakiViewSections(vpc, 'meraki').siteSections.map((s) => s.title)).toEqual([
      'VPC network overview',
      'VM instances',
    ]);
  });
});

describe('sourceTypeLabel', () => {
  it('names every kind of map source', () => {
    expect(['neighbors', 'meraki', 'cato', 'fmc', 'panorama', 'aws', 'azure', 'gcp'].map(sourceTypeLabel)).toEqual([
      'Neighbor discovery',
      'Meraki',
      'Cato',
      'Cisco FMC',
      'Palo Alto Panorama',
      'AWS',
      'Azure',
      'GCP',
    ]);
  });
});
