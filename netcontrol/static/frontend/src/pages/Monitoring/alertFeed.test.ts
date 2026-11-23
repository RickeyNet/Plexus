import { describe, expect, it } from 'vitest';

import type { MerakiAlert } from '@/api/merakiAlerts';
import type { VendorAlert } from '@/api/vendorAlerts';

import { alertViaText, feedStatusText, merakiAlertRow, pollSummary, vendorAlertRow } from './alertFeed';
import { vendorAlertFeedText } from './vendorAlertFeeds';

const cato: VendorAlert = {
  id: 1,
  provider: 'cato',
  alert_key: 'cato:7:uplink:1002:WAN 02:disconnected',
  org_ref: 7,
  org_name: 'Example Cato',
  entity_type: 'uplink',
  entity_id: '1002:WAN 02',
  entity_name: 'Branch-Madison WAN 02',
  site: 'Branch-Madison',
  serial: 'X1500-0003-CCCC',
  condition: 'disconnected',
  event_type: 'Connectivity',
  event_sub_type: 'Disconnected',
  title: 'Disconnected',
  message: 'Disconnected (demo)',
  severity: 'warning',
  status: 'open',
  auto_expire: false,
  started_at: '2026-11-20 08:00:00',
  resolved_at: '',
  first_seen: '2026-11-20 08:00:05',
  last_seen: '2026-11-20 08:00:05',
  occurrences: 1,
  host_id: null,
  alert_via: 'notification',
  muted: false,
};

describe('alert feed rows', () => {
  it('maps a vendor alert to a table row', () => {
    const row = vendorAlertRow(cato);
    expect(row.subject).toBe('Branch-Madison WAN 02');
    expect(row.where).toBe('Branch-Madison');
    expect(row.source).toBe('Example Cato');
    expect(row.via).toBe('Disconnected');
    expect(row.lastAt).toBe('2026-11-20 08:00:05');
    const site = vendorAlertRow({ ...cato, entity_name: 'Branch-Madison', status: 'resolved', resolved_at: '2026-11-20 09:00:00' });
    expect(site.where).toBe('');
    expect(site.lastAt).toBe('2026-11-20 09:00:00');
  });

  it('maps a Meraki alert to the same row shape', () => {
    const meraki = {
      alert_key: 'meraki:5:d:Q2XX:device_down',
      org_ref: 5,
      org_name: '',
      network_name: 'Lobby',
      device_serial: 'Q2XX',
      device_name: '',
      title: 'APs went down',
      message: 'APs went down',
      severity: 'critical',
      status: 'open',
      started_at: '2026-11-20 08:00:00',
      resolved_at: '',
      last_seen: '2026-11-20 08:01:00',
      seen_via: ['poll', 'webhook'],
      alert_via: 'muted',
      muted: true,
    } as unknown as MerakiAlert;
    const row = merakiAlertRow(meraki);
    expect(row.subject).toBe('Q2XX');
    expect(row.source).toBe('5');
    expect(row.via).toBe('poll, webhook');
    expect(row.muted).toBe(true);
  });

  it('labels how Plexus alerted and the feed status', () => {
    expect(alertViaText('topology', 'critical')).toBe('Already notified (availability)');
    expect(alertViaText('', 'info')).toBe('Listed only');
    expect(alertViaText('', 'warning')).toBe('-');
    expect(feedStatusText('positioned')).toBe('Started (reads from now on)');
    expect(feedStatusText('')).toBe('Not polled yet');
    expect(feedStatusText('something_new')).toBe('something_new');
  });

  it('summarises Poll Now', () => {
    expect(pollSummary({ ok: true, polled: 2, new: 1, resolved: 0 }, 'account')).toBe('Polled 2 account(s): 1 new, 0 resolved.');
    expect(pollSummary({ ok: false, polled: 0, error: 'unknown provider' }, 'account')).toBe('Poll failed: unknown provider.');
    expect(pollSummary({ ok: false, polled: 3, failed: 1 }, 'organization')).toContain('1 failed');
    expect(pollSummary({ ok: false, polled: 1, failed: 1 }, 'subscription', 'Cloud Visibility > Accounts')).toContain(
      'See Cloud Visibility > Accounts',
    );
  });

  it('names the feeds and a partial read', () => {
    expect(feedStatusText('partial')).toBe('Reading, in part');
    expect(vendorAlertFeedText('aws').settingsWhere).toBe('Cloud Visibility > Accounts');
    expect(vendorAlertFeedText('azure').sourceNoun).toBe('subscription');
    expect(vendorAlertFeedText('cato').securityEvents).toBe(true);
    expect(vendorAlertFeedText('other').title).toBe('other alerts');
  });
});
