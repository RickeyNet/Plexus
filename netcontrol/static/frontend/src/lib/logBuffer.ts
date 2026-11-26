import { useEffect, useState } from 'react';

/**
 * Lines a live log view keeps. A long job streams far more than anyone
 * scrolls back through, and every kept line is a DOM node.
 */
export const LOG_BUFFER_CAP = 5000;

/** What a log view shows: the kept lines in order, and how many earlier ones were dropped. */
export interface LogView<T> {
  readonly lines: readonly T[];
  readonly dropped: number;
}

const EMPTY_VIEW: LogView<never> = Object.freeze({ lines: Object.freeze([]) as readonly never[], dropped: 0 });

/** Runs `cb` before the next paint; returns a cancel function. */
export type FrameScheduler = (cb: () => void) => () => void;

const nextFrame: FrameScheduler = (cb) => {
  // A hidden tab runs no animation frames: the ring stays bounded meanwhile
  // and the view catches up in one update when the tab shows again.
  if (typeof requestAnimationFrame === 'function') {
    const id = requestAnimationFrame(cb);
    return () => cancelAnimationFrame(id);
  }
  const id = setTimeout(cb, 16);
  return () => clearTimeout(id);
};

export interface LogBuffer<T> {
  /** Adds a line; the view is published once per frame however many arrive. */
  push(line: T): void;
  /** Publishes pending lines now (a stream ended or is being torn down). */
  flush(): void;
  /** Empties the buffer and publishes the empty view; drops pending lines. */
  reset(): void;
  /** Stops a scheduled publish (the view is going away). */
  cancel(): void;
}

export interface LogBufferOptions<T> {
  /** Receives each published view. */
  onFlush: (view: LogView<T>) => void;
  cap?: number;
  schedule?: FrameScheduler;
}

/**
 * A capped ring buffer of log lines that publishes a fresh ordered copy at
 * most once per animation frame, so a burst of messages costs one state
 * update instead of a whole-array copy and re-render per message.
 */
export function createLogBuffer<T>({ onFlush, cap = LOG_BUFFER_CAP, schedule = nextFrame }: LogBufferOptions<T>): LogBuffer<T> {
  const ring: T[] = [];
  let start = 0;
  let dropped = 0;
  let dirty = false;
  let cancelFrame: (() => void) | null = null;
  let published = false;

  const publish = () => {
    cancelFrame?.();
    cancelFrame = null;
    if (!dirty) return;
    dirty = false;
    const lines = start === 0 ? ring.slice() : ring.slice(start).concat(ring.slice(0, start));
    published = true;
    onFlush({ lines, dropped });
  };

  return {
    push(line) {
      if (ring.length < cap) {
        ring.push(line);
      } else {
        ring[start] = line;
        start = (start + 1) % cap;
        dropped++;
      }
      dirty = true;
      cancelFrame ??= schedule(publish);
    },
    flush: publish,
    reset() {
      cancelFrame?.();
      cancelFrame = null;
      ring.length = 0;
      start = 0;
      dropped = 0;
      dirty = false;
      // Only a view that showed lines needs clearing; skipping the call keeps
      // a reset during render from scheduling a needless update.
      if (published) {
        published = false;
        onFlush(EMPTY_VIEW);
      }
    },
    cancel() {
      cancelFrame?.();
      cancelFrame = null;
    },
  };
}

/**
 * React state over a `LogBuffer`: `push` from a socket handler, render
 * `lines`. A scheduled publish is cancelled on unmount.
 */
export function useBufferedLog<T>(cap = LOG_BUFFER_CAP): LogView<T> & { buffer: LogBuffer<T> } {
  const [view, setView] = useState<LogView<T>>(EMPTY_VIEW);
  const [buffer] = useState(() => createLogBuffer<T>({ cap, onFlush: setView }));
  useEffect(() => () => buffer.cancel(), [buffer]);
  return { lines: view.lines, dropped: view.dropped, buffer };
}
