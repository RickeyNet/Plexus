import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { MONITORING_PAGE_SIZE, type MonitoringPoll, monitoringPollsPath } from '@/api/monitoring';

import { DevicesTab } from './DevicesTab';

// The tests render without a DOM, so typing and clicking are stood in for:
// the debounce hook returns what "was typed", the offset hook what the pager
// last set, and the Pager mock records the props the tab gives it.
const state = vi.hoisted(() => ({
  typed: '',
  offset: 0,
  setOffset: vi.fn(),
  pollArgs: [] as unknown[],
  pager: null as null | Record<string, unknown>,
  total: 450,
}));

vi.mock('@/lib/useDebouncedValue', () => ({ useDebouncedValue: () => state.typed }));
vi.mock('@/lib/useFilterOffset', () => ({ useFilterOffset: () => [state.offset, state.setOffset] }));
vi.mock('@/components/Pager', () => ({
  Pager: (props: Record<string, unknown>) => {
    state.pager = props;
    return null;
  },
}));

// Invented host in the shape of GET /api/monitoring/polls.
const POLL: MonitoringPoll = {
  host_id: 7,
  hostname: 'edge-sw-09.example.com',
  ip_address: '192.0.2.9',
  device_type: 'cisco_ios',
  if_up_count: 4,
  if_down_count: 0,
  if_admin_down: 0,
  vpn_tunnels_up: 0,
  vpn_tunnels_down: 0,
  route_count: 3,
  poll_status: 'ok',
};

vi.mock('@/api/monitoring', async (importOriginal) => {
  const real = await importOriginal<typeof import('@/api/monitoring')>();
  return {
    ...real,
    useMonitoringPolls: (q: unknown) => {
      state.pollArgs.push(q);
      return { data: { polls: [POLL], total: state.total }, isPending: false, error: null };
    },
    useMonitoringSummary: () => ({ data: undefined }),
    useMonitoringPollHistory: () => ({ data: undefined }),
  };
});

function render(): string {
  return renderToStaticMarkup(
    <MemoryRouter>
      <DevicesTab />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  state.typed = '';
  state.offset = 0;
  state.setOffset.mockReset();
  state.pollArgs = [];
  state.pager = null;
});

describe('DevicesTab', () => {
  it('sends what is typed in the search box to the server as q', () => {
    state.typed = 'edge-sw-09';
    const html = render();
    expect(state.pollArgs.at(-1)).toEqual({ q: 'edge-sw-09', offset: 0 });
    expect(html).toContain('edge-sw-09.example.com');
    expect(monitoringPollsPath({ q: 'edge-sw-09', limit: MONITORING_PAGE_SIZE, offset: 0 })).toBe(
      '/monitoring/polls?q=edge-sw-09&limit=200&offset=0&with_total=true',
    );
  });

  it('pages with the pager: Previous / Next move the offset the request carries', () => {
    render();
    expect(state.pager).toMatchObject({
      offset: 0,
      pageSize: MONITORING_PAGE_SIZE,
      total: 450,
      previousLabel: 'Previous',
      nextLabel: 'Next',
    });
    (state.pager?.onChange as (o: number) => void)(200);
    expect(state.setOffset).toHaveBeenCalledWith(200);

    state.offset = 200;
    render();
    expect(state.pollArgs.at(-1)).toEqual({ q: '', offset: 200 });
  });
});
