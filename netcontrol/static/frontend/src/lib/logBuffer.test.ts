import { describe, expect, it, vi } from 'vitest';

import { createLogBuffer, type LogView } from './logBuffer';

// A scheduler the test runs by hand: `frame()` is the next animation frame.
function manualFrames() {
  let pending: (() => void) | null = null;
  const schedule = vi.fn((cb: () => void) => {
    pending = cb;
    return () => {
      if (pending === cb) pending = null;
    };
  });
  return {
    schedule,
    frame() {
      const cb = pending;
      pending = null;
      cb?.();
    },
    get scheduled() {
      return pending != null;
    },
  };
}

function setup(cap = 5) {
  const frames = manualFrames();
  const views: LogView<number>[] = [];
  const buffer = createLogBuffer<number>({ cap, schedule: frames.schedule, onFlush: (v) => views.push(v) });
  return { frames, views, buffer };
}

describe('createLogBuffer', () => {
  it('publishes a burst once per frame, in order', () => {
    const { frames, views, buffer } = setup(100);
    for (let i = 0; i < 50; i++) buffer.push(i);
    expect(views).toHaveLength(0);
    expect(frames.schedule).toHaveBeenCalledTimes(1);

    frames.frame();
    expect(views).toHaveLength(1);
    expect(views[0].lines).toEqual(Array.from({ length: 50 }, (_, i) => i));
    expect(views[0].dropped).toBe(0);
  });

  it('keeps only the newest lines and counts the dropped ones', () => {
    const { frames, views, buffer } = setup(5);
    for (let i = 1; i <= 12; i++) buffer.push(i);
    frames.frame();
    expect(views.at(-1)).toEqual({ lines: [8, 9, 10, 11, 12], dropped: 7 });

    buffer.push(13);
    frames.frame();
    expect(views.at(-1)).toEqual({ lines: [9, 10, 11, 12, 13], dropped: 8 });
  });

  it('flushes the tail at once when the stream ends', () => {
    const { frames, views, buffer } = setup();
    buffer.push(1);
    buffer.push(2);
    buffer.flush();
    expect(views).toEqual([{ lines: [1, 2], dropped: 0 }]);
    // The frame was cancelled; nothing is published twice.
    expect(frames.scheduled).toBe(false);
    buffer.flush();
    expect(views).toHaveLength(1);
  });

  it('publishes nothing after cancel (unmount)', () => {
    const { frames, views, buffer } = setup();
    buffer.push(1);
    buffer.cancel();
    frames.frame();
    expect(views).toHaveLength(0);
  });

  it('reset drops pending lines and clears a shown view once', () => {
    const { frames, views, buffer } = setup();
    buffer.push(1);
    frames.frame();
    buffer.push(2);
    buffer.reset();
    frames.frame();
    expect(views).toEqual([{ lines: [1], dropped: 0 }, { lines: [], dropped: 0 }]);
    // Nothing shown now: a second reset (a render-phase reset) publishes nothing.
    buffer.reset();
    expect(views).toHaveLength(2);
    // A flush after reset (a socket torn down for the next job) adds nothing.
    buffer.flush();
    expect(views).toHaveLength(2);
  });
});
