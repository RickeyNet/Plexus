import { renderToStaticMarkup } from 'react-dom/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { type MonitoringAlert, monitoringAlertsPath } from '@/api/monitoring';

import { AlertsTab } from './AlertsTab';
import { ROUTE_CHURN, alertsFilter } from './helpers';

// Rendered without a DOM: the offset hook stands in for the pager's last
// click and the Pager mock records the props the tab gives it.
const state = vi.hoisted(() => ({
  offset: 0,
  setOffset: vi.fn(),
  alertArgs: [] as unknown[],
  pager: null as null | Record<string, unknown>,
}));

vi.mock('@/lib/useFilterOffset', () => ({ useFilterOffset: () => [state.offset, state.setOffset] }));
vi.mock('@/components/Pager', () => ({
  Pager: (props: Record<string, unknown>) => {
    state.pager = props;
    return null;
  },
}));
vi.mock('@/components/DialogProvider-context', () => ({ useDialogs: () => ({ alert: vi.fn(), confirm: vi.fn() }) }));

// Invented alert in the shape of GET /api/monitoring/alerts.
const ALERT: MonitoringAlert = {
  id: 11,
  host_id: 7,
  hostname: 'edge-rtr-02.example.com',
  ip_address: '198.51.100.2',
  metric: ROUTE_CHURN,
  severity: 'warning',
  message: 'Route table changed by 12 routes',
  acknowledged: false,
};

vi.mock('@/api/monitoring', async (importOriginal) => {
  const real = await importOriginal<typeof import('@/api/monitoring')>();
  const idle = { mutate: vi.fn(), mutateAsync: vi.fn(), isPending: false };
  return {
    ...real,
    useMonitoringAlerts: (q: unknown) => {
      state.alertArgs.push(q);
      return { data: { alerts: [ALERT], total: 450 }, isPending: false, error: null };
    },
    useAcknowledgeAlert: () => idle,
    useBulkAcknowledgeAlerts: () => idle,
  };
});

beforeEach(() => {
  state.offset = 0;
  state.setOffset.mockReset();
  state.alertArgs = [];
  state.pager = null;
});

describe('AlertsTab', () => {
  it('asks the server for the open alerts, newest page first', () => {
    const html = renderToStaticMarkup(<AlertsTab />);
    expect(state.alertArgs.at(-1)).toEqual({ acknowledged: false, severity: '', q: '', metric: '', offset: 0 });
    expect(html).toContain('edge-rtr-02.example.com');
    expect(state.pager).toMatchObject({ offset: 0, pageSize: 200, total: 450 });
    (state.pager?.onChange as (o: number) => void)(200);
    expect(state.setOffset).toHaveBeenCalledWith(200);
  });

  it('sends the route churn toggle, search and severity as server filters', () => {
    const filter = alertsFilter({ ackFilter: 'all', severity: 'critical', search: 'edge', routeChurnOnly: true });
    expect(filter).toEqual({ acknowledged: null, severity: 'critical', q: 'edge', metric: ROUTE_CHURN });
    expect(monitoringAlertsPath({ ...filter, limit: 200, offset: 200 })).toBe(
      '/monitoring/alerts?severity=critical&q=edge&metric=route_churn&limit=200&offset=200&with_total=true',
    );
    expect(alertsFilter({ ackFilter: 'ack', severity: '', search: '', routeChurnOnly: false })).toMatchObject({
      acknowledged: true,
      metric: '',
    });
  });
});
