import { describe, expect, it } from 'vitest';

import type { DetailSection, MerakiNodeDetails } from '@/api/meraki';

import {
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

describe('anyconnect detail tabs', () => {
  it('files headend and policy sections under the shared tabs', () => {
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

describe('sourceTypeLabel', () => {
  it('names every kind of map source', () => {
    expect(['neighbors', 'meraki', 'cato', 'anyconnect', 'aws', 'azure'].map(sourceTypeLabel)).toEqual([
      'Neighbor discovery',
      'Meraki',
      'Cato',
      'AnyConnect (FMC)',
      'AWS',
      'Azure',
    ]);
  });
});
