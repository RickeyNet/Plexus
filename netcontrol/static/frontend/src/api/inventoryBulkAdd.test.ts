import { describe, expect, it } from 'vitest';

import {
  BULK_ADD_MAX_HOSTS,
  bulkAddHostsInChunks,
  chunkBulkAddBody,
  type BulkAddHostsRequest,
  type BulkAddHostsResult,
} from './inventory';

function body(count: number, groupId?: number): BulkAddHostsRequest {
  const hosts = Array.from({ length: count }, (_, i) => ({
    hostname: `h${i}`,
    ip_address: `192.0.2.${i % 250}`,
    device_type: 'icmp_only',
  }));
  return groupId == null ? { hosts } : { group_id: groupId, hosts };
}

/** A backend stand-in that adds every host it is sent. */
function addAll(chunk: BulkAddHostsRequest): Promise<BulkAddHostsResult> {
  return Promise.resolve({
    added: chunk.hosts.map((h, i) => ({ id: i, hostname: h.hostname, ip_address: h.ip_address, group_id: 1, group_name: 'g', group_path: 'g' })),
    skipped: [],
    errors: [],
    groups_created: [],
  });
}

describe('chunkBulkAddBody', () => {
  it('splits the hosts into requests of the backend limit, keeping the group', () => {
    const chunks = chunkBulkAddBody(body(BULK_ADD_MAX_HOSTS * 2 + 3, 4));
    expect(chunks.map((c) => c.hosts.length)).toEqual([BULK_ADD_MAX_HOSTS, BULK_ADD_MAX_HOSTS, 3]);
    expect(chunks.every((c) => c.group_id === 4)).toBe(true);
    expect(chunks[1].hosts[0].hostname).toBe(`h${BULK_ADD_MAX_HOSTS}`);
    expect(chunkBulkAddBody(body(0))).toEqual([]);
  });
});

describe('bulkAddHostsInChunks', () => {
  it('sends every chunk in order, merging the results and reporting progress', async () => {
    const progress: number[] = [];
    const run = await bulkAddHostsInChunks(body(1203), { onProgress: (done) => progress.push(done) }, addAll);
    expect(run).toMatchObject({ attempted: 1203, total: 1203, stopped: false, error: null });
    expect(run.result.added).toHaveLength(1203);
    expect(progress).toEqual([500, 1000, 1203]);
  });

  it('stops between chunks when asked', async () => {
    let sent = 0;
    const run = await bulkAddHostsInChunks(body(1203), { shouldStop: () => sent >= 1 }, (chunk) => {
      sent += 1;
      return addAll(chunk);
    });
    expect(run).toMatchObject({ attempted: 500, total: 1203, stopped: true, error: null });
    expect(run.result.added).toHaveLength(500);
  });

  it('ends on a failed request with what the earlier ones did', async () => {
    let calls = 0;
    const run = await bulkAddHostsInChunks(body(1203), {}, (chunk) => {
      calls += 1;
      return calls === 2 ? Promise.reject(new Error('Gateway timeout')) : addAll(chunk);
    });
    expect(run).toMatchObject({ attempted: 500, total: 1203, stopped: false, error: 'Gateway timeout' });
    expect(run.result.added).toHaveLength(500);
    expect(calls).toBe(2);
  });
});
