import { QueryClient } from '@tanstack/react-query';
import { describe, expect, it, vi } from 'vitest';

import { applyCampaignCacheEvent } from './upgrades';

function spiedClient(): QueryClient {
  const qc = new QueryClient();
  vi.spyOn(qc, 'invalidateQueries');
  return qc;
}

function invalidatedKeys(qc: QueryClient): unknown[] {
  return vi.mocked(qc.invalidateQueries).mock.calls.map(([filters]) => filters?.queryKey);
}

describe('applyCampaignCacheEvent', () => {
  it('refetches inventory, the map and the software tracker when a verified version reached its host', () => {
    const qc = spiedClient();

    expect(applyCampaignCacheEvent(qc, 12, 'inventory_updated')).toBe(true);

    expect(invalidatedKeys(qc)).toEqual(
      expect.arrayContaining([
        ['inventory-groups-full'],
        ['inventory-groups'],
        ['topology'],
        ['software-overview'],
      ]),
    );
  });

  it('refetches the campaign and the campaign list when the campaign completes', () => {
    const qc = spiedClient();

    expect(applyCampaignCacheEvent(qc, 12, 'campaign_complete')).toBe(true);

    expect(invalidatedKeys(qc)).toEqual([['upgrade-campaign', 12], ['upgrade-campaigns']]);
  });

  it('leaves every other event to the caller', () => {
    const qc = spiedClient();

    for (const type of ['device_status', 'upgrade_event', 'transfer_progress', undefined]) {
      expect(applyCampaignCacheEvent(qc, 12, type)).toBe(false);
    }
    expect(qc.invalidateQueries).not.toHaveBeenCalled();
  });
});
