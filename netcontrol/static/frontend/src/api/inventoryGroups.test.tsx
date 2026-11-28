import { QueryClient, QueryClientProvider, QueryObserver } from '@tanstack/react-query';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  type InventoryGroupFull,
  inventoryGroupKeys,
  inventoryGroupsQueryOptions,
  invalidateInventory,
  selectHostOptions,
  useHostOptions,
  useInventoryGroups,
  useInventoryGroupsFull,
} from './inventory';

const GROUPS: InventoryGroupFull[] = [
  {
    id: 1,
    name: 'core',
    path: 'site-a / core',
    hosts: [
      { id: 11, hostname: 'sw-b', ip_address: '192.0.2.11', status: 'up' },
      { id: 12, hostname: '', ip_address: '192.0.2.12' },
    ],
  },
  {
    id: 2,
    name: 'edge',
    hosts: [
      { id: 21, hostname: 'rtr-a', ip_address: '198.51.100.21' },
      // The same host listed again keeps its first group.
      { id: 11, hostname: 'sw-b', ip_address: '192.0.2.11' },
    ],
  },
];

/** A fetch that answers each `/api/inventory` request from `answer(url)`. */
function stubFetch(answer: (url: string) => unknown) {
  const fetchMock = vi.fn(async (url: string) =>
    new Response(JSON.stringify(answer(url)), { headers: { 'content-type': 'application/json' } }),
  );
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

function client() {
  return new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 30_000 } } });
}

/** Waits until `check` passes (the observers settle asynchronously). */
async function until(check: () => void) {
  for (let i = 0; i < 50; i += 1) {
    try {
      check();
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
  }
  check();
}

afterEach(() => vi.unstubAllGlobals());

describe('selectHostOptions', () => {
  it('lists each host once, sorted by label, with its group', () => {
    expect(selectHostOptions(GROUPS)).toEqual([
      {
        id: 12,
        hostname: '',
        ip_address: '192.0.2.12',
        status: undefined,
        label: '192.0.2.12',
        group_id: 1,
        group_name: 'site-a / core',
      },
      {
        id: 21,
        hostname: 'rtr-a',
        ip_address: '198.51.100.21',
        status: undefined,
        label: 'rtr-a',
        group_id: 2,
        group_name: 'edge',
      },
      {
        id: 11,
        hostname: 'sw-b',
        ip_address: '192.0.2.11',
        status: 'up',
        label: 'sw-b',
        group_id: 1,
        group_name: 'site-a / core',
      },
    ]);
  });

  it('falls back to host-<id> without a hostname or address', () => {
    expect(selectHostOptions([{ id: 1, name: 'g', hosts: [{ id: 5, hostname: '', ip_address: '' }] }])[0].label).toBe(
      'host-5',
    );
  });

  it('is empty for a groups-only listing', () => {
    expect(selectHostOptions([{ id: 1, name: 'g' }])).toEqual([]);
  });
});

describe('the shared inventory listing', () => {
  it('serves every consumer of the full listing from one request', async () => {
    const fetchMock = stubFetch(() => GROUPS);
    const qc = client();
    const options = inventoryGroupsQueryOptions(true);
    const groups = new QueryObserver(qc, options);
    const hosts = new QueryObserver(qc, { ...options, select: selectHostOptions });
    const names = new QueryObserver(qc, { ...options, select: (g: InventoryGroupFull[]) => g.map((x) => x.name) });
    const stops = [groups, hosts, names].map((o) => o.subscribe(() => {}));

    await until(() => expect(hosts.getCurrentResult().data).toHaveLength(3));
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe('/api/inventory?include_hosts=true');
    expect(groups.getCurrentResult().data).toEqual(GROUPS);
    expect(names.getCurrentResult().data).toEqual(['core', 'edge']);
    expect(qc.getQueryCache().findAll({ queryKey: inventoryGroupKeys.all })).toHaveLength(1);
    stops.forEach((stop) => stop());
  });

  it('keeps the selected host options identical while the listing is unchanged', async () => {
    const fetchMock = stubFetch(() => GROUPS);
    const qc = client();
    const hosts = new QueryObserver(qc, { ...inventoryGroupsQueryOptions(true), select: selectHostOptions });
    const stop = hosts.subscribe(() => {});
    await until(() => expect(hosts.getCurrentResult().data).toHaveLength(3));
    const first = hosts.getCurrentResult().data;

    // A refetch with equal content: structural sharing keeps the data, so the
    // selector's result keeps its identity and no picker re-renders.
    await qc.refetchQueries({ queryKey: inventoryGroupKeys.all });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(hosts.getCurrentResult().data).toBe(first);
    stop();
  });

  it('refreshes every consumer of both listings with one invalidation', async () => {
    let version = 0;
    const fetchMock = stubFetch((url) =>
      url.includes('include_hosts')
        ? [{ ...GROUPS[0], hosts: [...(GROUPS[0].hosts ?? []), ...(version ? [{ id: 31, hostname: 'fw-c', ip_address: '203.0.113.31' }] : [])] }]
        : [{ id: 1, name: version ? 'core-renamed' : 'core', host_count: 2 }],
    );
    const qc = client();
    const full = new QueryObserver(qc, inventoryGroupsQueryOptions(true));
    const hosts = new QueryObserver(qc, { ...inventoryGroupsQueryOptions(true), select: selectHostOptions });
    const light = new QueryObserver(qc, inventoryGroupsQueryOptions(false));
    const stops = [full, hosts, light].map((o) => o.subscribe(() => {}));
    await until(() => expect(light.getCurrentResult().data).toBeDefined());
    await until(() => expect(hosts.getCurrentResult().data).toHaveLength(2));
    expect(fetchMock).toHaveBeenCalledTimes(2);

    version = 1;
    const spy = vi.spyOn(qc, 'invalidateQueries');
    invalidateInventory(qc);

    expect(spy).toHaveBeenCalledTimes(1);
    await until(() => expect(hosts.getCurrentResult().data?.map((h) => h.label)).toContain('fw-c'));
    await until(() => expect(light.getCurrentResult().data?.[0].name).toBe('core-renamed'));
    expect(full.getCurrentResult().data?.[0].hosts).toHaveLength(3);
    // One request per listing, not one per consumer.
    expect(fetchMock).toHaveBeenCalledTimes(4);
    stops.forEach((stop) => stop());
  });
});

describe('the inventory hooks', () => {
  function Consumers() {
    const full = useInventoryGroupsFull(true);
    const light = useInventoryGroups();
    const hosts = useHostOptions();
    return (
      <p>
        {full.data?.length} groups; {light.data?.map((g) => g.name).join(',')};{' '}
        {hosts.data?.map((h) => `${h.label}@${h.group_name}`).join(',')}
      </p>
    );
  }

  it('read the cached listings under the shared keys', () => {
    const qc = client();
    qc.setQueryData(inventoryGroupKeys.list(true), GROUPS);
    qc.setQueryData(inventoryGroupKeys.list(false), [{ id: 1, name: 'core' }, { id: 2, name: 'edge' }]);
    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <Consumers />
      </QueryClientProvider>,
    );
    expect(html).toContain('2 groups; core,edge; 192.0.2.12@site-a / core,rtr-a@edge,sw-b@site-a / core');
  });
});
