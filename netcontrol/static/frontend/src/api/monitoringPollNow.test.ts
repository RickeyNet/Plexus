import { afterEach, describe, expect, it, vi } from 'vitest';

import { streamPollNow } from './monitoring';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('streamPollNow', () => {
  it("shows the message of a 409 (a poll is already running), not the raw JSON", async () => {
    const body = {
      ok: false,
      error: { code: 'http_error', message: 'A manual monitoring poll is already running. Try again when it finishes.' },
    };
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify(body), { status: 409, headers: { 'Content-Type': 'application/json' } })),
    );
    await expect(streamPollNow(() => {})).rejects.toThrow(
      /^A manual monitoring poll is already running\. Try again when it finishes\.$/,
    );
  });

  it('falls back to the body text, then to the status', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('Bad gateway', { status: 502 })));
    await expect(streamPollNow(() => {})).rejects.toThrow('Bad gateway');
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 500 })));
    await expect(streamPollNow(() => {})).rejects.toThrow('Poll stream failed: 500');
  });

  it('passes an error event on to the caller', async () => {
    const events: unknown[] = [];
    const sse = 'data: {"type": "error", "error": "A manual monitoring poll is already running."}\n\n';
    vi.stubGlobal('fetch', vi.fn(async () => new Response(sse, { status: 200 })));
    await streamPollNow((event) => events.push(event));
    expect(events).toEqual([{ type: 'error', error: 'A manual monitoring poll is already running.' }]);
  });
});
