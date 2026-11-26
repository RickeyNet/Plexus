import { renderToStaticMarkup } from 'react-dom/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { CloudConnection, CloudHybridLink, CloudResource, CloudTopology } from '@/api/cloud';

import { TopologyTab } from './TopologyTab';

const state = vi.hoisted(() => ({ topology: {} as Record<string, unknown> }));

vi.mock('@/api/cloud', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/api/cloud')>()),
  useCloudTopology: () => state.topology,
}));

function resource(i: number, type = 'vpc'): CloudResource {
  return {
    id: i,
    resource_uid: `${type}-${i}`,
    provider: 'aws',
    resource_type: type,
    name: `${type}-name-${i}`,
    region: 'us-east-1',
    cidr: `198.51.100.${i % 256}/32`,
  };
}

function connection(i: number): CloudConnection {
  return {
    id: i,
    provider: 'aws',
    source_resource_uid: `vpc-${i}`,
    target_resource_uid: `vpc-${i + 1}`,
    connection_type: 'peering',
    state: 'active',
  };
}

function hybridLink(i: number): CloudHybridLink {
  return { id: i, provider: 'aws', host_hostname: `edge-${i}.example.com`, cloud_resource_uid: `vpc-${i}` };
}

function render(data: Partial<CloudTopology>): string {
  state.topology = {
    isError: false,
    isPending: false,
    isFetching: false,
    error: null,
    refetch: () => {},
    data: { resources: [], connections: [], hybrid_links: [], summary: {}, ...data },
  };
  return renderToStaticMarkup(<TopologyTab filter={{ provider: '', accountId: null }} />);
}

const count = (html: string, needle: string) => html.split(needle).length - 1;

describe('TopologyTab list caps', () => {
  beforeEach(() => {
    state.topology = {};
  });

  it('renders the first 200 resources, connections and hybrid links with a Show more button each', () => {
    const resources = Array.from({ length: 250 }, (_, i) => resource(i));
    const connections = Array.from({ length: 230 }, (_, i) => connection(i));
    const hybrid = Array.from({ length: 210 }, (_, i) => hybridLink(i));
    const html = render({ resources, connections, hybrid_links: hybrid });

    expect(count(html, '>vpc-name-')).toBe(200);
    expect(html).not.toContain('>vpc-name-200<');
    expect(count(html, '>edge-')).toBe(200);
    expect(html).toContain('Show more (50 hidden)');
    expect(html).toContain('Show more (30 hidden)');
    expect(html).toContain('Show more (10 hidden)');
  });

  it('shows no Show more button when every list fits', () => {
    const html = render({
      resources: [resource(1), resource(2)],
      connections: [connection(1)],
      hybrid_links: [hybridLink(1)],
    });
    expect(html).not.toContain('Show more');
  });

  it('caps the route objects of a provider group', () => {
    const routes = Array.from({ length: 205 }, (_, i) => resource(i, 'route_table'));
    const html = render({ resources: routes });
    // Each route object appears once in the route-path table and once in Resources.
    expect(count(html, '>route_table-name-')).toBe(400);
    expect(html).toContain('Show more (5 hidden)');
  });
});
