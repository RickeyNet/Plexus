import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { PollNowEvent } from '@/api/monitoring';

const mocks = vi.hoisted(() => ({
  // The test drives the stream: events go to `emit`, `finish` ends it.
  emit: null as null | ((event: PollNowEvent) => void),
  finish: null as null | (() => void),
}));

vi.mock('@/api/monitoring', () => ({
  streamPollNow: (onEvent: (event: PollNowEvent) => void) =>
    new Promise<void>((resolve) => {
      mocks.emit = onEvent;
      mocks.finish = resolve;
    }),
}));

let frames: (() => void)[] = [];

beforeEach(() => {
  frames = [];
  vi.stubGlobal('requestAnimationFrame', (cb: () => void) => frames.push(cb));
  vi.stubGlobal('cancelAnimationFrame', (id: number) => {
    frames[id - 1] = () => {};
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.resetModules();
});

function runFrames() {
  const pending = frames;
  frames = [];
  for (const cb of pending) cb();
}

function host(i: number): PollNowEvent {
  return { type: 'host_done', status: 'ok', hostname: `edge-${i}`, completed: i, total_hosts: 6000 } as PollNowEvent;
}

describe('poll-now progress', () => {
  it('publishes a burst of host lines once per frame and keeps the tail on done', async () => {
    const store = await import('./pollNowStore');
    const seen: number[] = [];
    const unsubscribe = store.subscribePollProgress((s) => seen.push(s.log.length));

    const run = store.startPollNow();
    mocks.emit?.({ type: 'start', total_hosts: 6000 } as PollNowEvent);
    const before = seen.length;

    for (let i = 1; i <= 300; i++) mocks.emit?.(host(i));
    expect(seen.length).toBe(before);

    runFrames();
    expect(seen.length).toBe(before + 1);
    const progress = store.getPollProgress();
    expect(progress.log).toHaveLength(300);
    expect(progress.log[0].hostname).toBe('edge-1');
    expect(progress.log[299].hostname).toBe('edge-300');
    expect(progress.completed).toBe(300);

    // Lines of the last frame are published with the done event, not lost.
    for (let i = 301; i <= 6000; i++) mocks.emit?.(host(i));
    mocks.emit?.({ type: 'done', hosts_polled: 6000, alerts_created: 0, errors: 0 } as PollNowEvent);
    mocks.finish?.();
    await run;

    const done = store.getPollProgress();
    expect(done.active).toBe(false);
    expect(done.log).toHaveLength(5000);
    expect(done.logDropped).toBe(1000);
    expect(done.log[0].hostname).toBe('edge-1001');
    expect(done.log[4999].hostname).toBe('edge-6000');
    unsubscribe();
  });
});
