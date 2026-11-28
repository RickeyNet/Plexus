import { QueryClient } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  invalidateTopologyGroupMaps,
  invalidateTopologyMaps,
  openUtilizationStream,
  topologyMapKey,
  topologyOverlayStatusKey,
} from './topology';

describe('topology query keys', () => {
  it('keys the all-groups map as null and a group by its number', () => {
    expect(topologyMapKey()).toEqual(['topology', null]);
    expect(topologyMapKey(null)).toEqual(['topology', null]);
    expect(topologyMapKey('')).toEqual(['topology', null]);
    expect(topologyMapKey(7)).toEqual(['topology', 7]);
    expect(topologyMapKey('7')).toEqual(['topology', 7]);
  });
});

describe('topology map invalidation', () => {
  let qc: QueryClient;

  // Cached maps of two groups and of all groups, plus the status overlay.
  beforeEach(() => {
    qc = new QueryClient();
    for (const key of [topologyMapKey(null), topologyMapKey(3), topologyMapKey(4), topologyOverlayStatusKey]) {
      qc.setQueryData(key, {});
    }
  });

  function invalidated(): unknown[] {
    return qc
      .getQueryCache()
      .getAll()
      .filter((q) => q.state.isInvalidated)
      .map((q) => q.queryKey);
  }

  it("refetches one group's map and the all-groups map, exactly", async () => {
    await invalidateTopologyGroupMaps(qc, 3);
    expect(invalidated()).toEqual([['topology', null], ['topology', 3]]);
  });

  it('refetches every map for the all-groups view', async () => {
    await invalidateTopologyGroupMaps(qc, null);
    expect(invalidated()).toEqual([['topology', null], ['topology', 3], ['topology', 4]]);
  });

  it('refetches every map but not the status overlay', async () => {
    await invalidateTopologyMaps(qc);
    expect(invalidated()).toEqual([['topology', null], ['topology', 3], ['topology', 4]]);
  });

  it('names the topology family, for callers that check the keys they refresh', () => {
    const spy = vi.spyOn(qc, 'invalidateQueries');
    void invalidateTopologyMaps(qc);
    expect(spy.mock.calls[0][0]?.queryKey).toEqual(['topology']);
  });
});

describe('openUtilizationStream', () => {
  class FakeEventSource {
    static opened: FakeEventSource[] = [];
    closed = false;
    onmessage: ((event: { data: string }) => void) | null = null;
    onerror: (() => void) | null = null;
    constructor(public url: string) {
      FakeEventSource.opened.push(this);
    }
    close() {
      this.closed = true;
    }
  }

  let doc: EventTarget & { visibilityState: DocumentVisibilityState };

  function setHidden(hidden: boolean) {
    doc.visibilityState = hidden ? 'hidden' : 'visible';
    doc.dispatchEvent(new Event('visibilitychange'));
  }

  beforeEach(() => {
    FakeEventSource.opened = [];
    doc = Object.assign(new EventTarget(), { visibilityState: 'visible' as DocumentVisibilityState });
    vi.stubGlobal('document', doc);
    vi.stubGlobal('EventSource', FakeEventSource);
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it('closes while the page is hidden and opens again when it is shown', () => {
    const onEdges = vi.fn();
    const stop = openUtilizationStream(30, onEdges);
    expect(FakeEventSource.opened).toHaveLength(1);
    expect(FakeEventSource.opened[0].url).toBe('/api/topology/utilization/stream?interval=30');

    setHidden(true);
    expect(FakeEventSource.opened[0].closed).toBe(true);
    // No reconnect behind the operator's back while hidden.
    vi.advanceTimersByTime(60_000);
    expect(FakeEventSource.opened).toHaveLength(1);

    setHidden(false);
    expect(FakeEventSource.opened).toHaveLength(2);
    // The server's first push on the new stream reaches the map at once.
    const edges = [{ source_host_id: 1, target_host_id: 2, source_interface: 'Gi0/1', utilization: { utilization_pct: 12 } }];
    FakeEventSource.opened[1].onmessage?.({ data: JSON.stringify({ edges }) });
    expect(onEdges).toHaveBeenCalledWith(edges);

    stop();
    expect(FakeEventSource.opened[1].closed).toBe(true);
    setHidden(true);
    setHidden(false);
    expect(FakeEventSource.opened).toHaveLength(2);
  });

  it('does not open in a hidden tab, and opens once shown', () => {
    doc.visibilityState = 'hidden';
    const stop = openUtilizationStream(30, () => {});
    expect(FakeEventSource.opened).toHaveLength(0);
    setHidden(false);
    expect(FakeEventSource.opened).toHaveLength(1);
    stop();
  });

  it('reconnects after an error while visible, but not once hidden', () => {
    const stop = openUtilizationStream(30, () => {});
    FakeEventSource.opened[0].onerror?.();
    expect(FakeEventSource.opened[0].closed).toBe(true);
    vi.advanceTimersByTime(10_000);
    expect(FakeEventSource.opened).toHaveLength(2);

    FakeEventSource.opened[1].onerror?.();
    setHidden(true);
    vi.advanceTimersByTime(10_000);
    expect(FakeEventSource.opened).toHaveLength(2);
    stop();
  });
});
