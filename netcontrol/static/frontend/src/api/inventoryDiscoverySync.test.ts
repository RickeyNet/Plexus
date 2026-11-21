import { QueryClient } from '@tanstack/react-query';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { type ScanStreamEvent, streamSyncInventoryGroup } from './inventory';

/** A `fetch` that answers every request with `lines` as a streamed body. */
function stubFetch(lines: string[], status = 200) {
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const line of lines) controller.enqueue(new TextEncoder().encode(`${line}\n`));
      controller.close();
    },
  });
  vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(new Response(body, { status }))));
}

function invalidatedKeys(qc: QueryClient): unknown[] {
  return vi.mocked(qc.invalidateQueries).mock.calls.map(([filters]) => filters?.queryKey?.[0]);
}

function spiedClient(): QueryClient {
  const qc = new QueryClient();
  vi.spyOn(qc, 'invalidateQueries');
  return qc;
}

afterEach(() => vi.unstubAllGlobals());

describe('streamSyncInventoryGroup', () => {
  it('refetches what a sync changes once the stream ends', async () => {
    stubFetch([
      'data: {"type":"start","total":1}',
      'data: {"type":"progress","scanned":1,"total":1,"ip":"192.0.2.10","found":true}',
      'data: {"type":"done","sync":{"added":0,"updated":1,"removed":0}}',
    ]);
    const qc = spiedClient();
    const events: ScanStreamEvent[] = [];

    await streamSyncInventoryGroup(qc, 7, ['192.0.2.10/32'], {}, (event) => events.push(event));

    expect(events.map((e) => e.type)).toEqual(['start', 'progress', 'done']);
    // The host rows (model, software version), the map and the software tracker.
    expect(invalidatedKeys(qc)).toEqual(
      expect.arrayContaining(['inventory-groups-full', 'inventory-groups', 'topology', 'software-overview']),
    );
  });

  it('refetches after a failed stream too: part of the sync may be stored', async () => {
    stubFetch(['upstream timed out'], 504);
    const qc = spiedClient();

    await expect(streamSyncInventoryGroup(qc, 7, [], {}, () => undefined)).rejects.toThrow('upstream timed out');

    expect(invalidatedKeys(qc)).toContain('inventory-groups-full');
  });
});
