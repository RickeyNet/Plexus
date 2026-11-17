import { describe, expect, it } from 'vitest';

import {
  droppedNote,
  historyWorthy,
  pathHistoryKey,
  pathHistoryLabel,
  reachabilityHistoryLabel,
  restorePicks,
  restoreReachabilityForm,
  restoreSummarizeForm,
  summarizeHistoryLabel,
} from './history';
import type { PathPick } from './paths';
import { emptySummarizeForm } from './summarizeHelpers';
import { emptyFilters, emptyForm, type ReachabilityForm } from './sweep';

const core: PathPick = { key: 'n:1', node: 1, label: 'core-sw-01' };
const branch: PathPick = { key: 'n:edge-7', node: 'edge-7', label: 'branch-fw' };
const app: PathPick = { key: 'app:example.com', label: 'example.com', app: 'example.com' };

describe('path trace history', () => {
  it('keeps a trace once it has two ends', () => {
    expect(historyWorthy([core])).toBe(false);
    expect(historyWorthy([core, branch])).toBe(true);
  });

  it('labels a trace by its ends and traffic', () => {
    expect(pathHistoryLabel({ picks: [core, branch], traffic: '' })).toBe('core-sw-01 → branch-fw');
    expect(pathHistoryLabel({ picks: [core, app], traffic: 'tcp/443' })).toBe('core-sw-01 → example.com · tcp/443');
  });

  it('keys a trace by its pick keys and traffic, not the records the picks carry', () => {
    const renamed = { ...core, label: 'core-sw-01 · HQ' };
    expect(pathHistoryKey({ picks: [core, branch], traffic: 'TCP/443 ' })).toBe(
      pathHistoryKey({ picks: [renamed, branch], traffic: 'tcp/443' }),
    );
    expect(pathHistoryKey({ picks: [core, branch], traffic: '' })).not.toBe(pathHistoryKey({ picks: [branch, core], traffic: '' }));
  });

  it('leaves out devices no longer on the map but keeps applications', () => {
    const onMap = (node: number | string) => node === 1;
    const restored = restorePicks([core, branch, app], onMap);
    expect(restored.picks).toEqual([core, app]);
    expect(restored.dropped).toEqual(['branch-fw']);
    expect(droppedNote(restored.dropped)).toBe('branch-fw is no longer on the map, so it was left out of the trace.');
    expect(droppedNote([])).toBe('');
    expect(droppedNote(['a', 'b'])).toBe('a, b are no longer on the map, so they were left out of the trace.');
  });
});

describe('reachability history', () => {
  it('labels a sweep by its ends and traffic', () => {
    const form = { ...emptyForm(), destination: '192.0.2.10', traffic: 'tcp/445' };
    const picked = { source: '', destination: '' };
    expect(reachabilityHistoryLabel({ form, picked })).toBe('source networks → 192.0.2.10 · tcp/445');
    expect(reachabilityHistoryLabel({ form: { ...form, source: '198.51.100.0/24', destination: '', traffic: '' }, picked })).toBe(
      '198.51.100.0/24 → destination networks · any traffic',
    );
  });

  it('fills fields a kept form lacks with their defaults', () => {
    const old = { source: '', destination: '192.0.2.10', traffic: 'icmp', to: {} } as unknown as ReachabilityForm;
    const form = restoreReachabilityForm({ form: old, picked: { source: '', destination: '' } });
    expect(form.destination).toBe('192.0.2.10');
    expect(form.kinds).toEqual(emptyForm().kinds);
    expect(form.to).toEqual(emptyFilters());
  });
});

describe('summarize history', () => {
  it('labels a summary by its first addresses, roll-up and cap', () => {
    const form = { ...emptySummarizeForm(), addresses: '192.0.2.1\n192.0.2.2, 192.0.2.3;198.51.100.4 203.0.113.0/24', prefix: '24', maxRoutes: '4' };
    expect(summarizeHistoryLabel(form)).toBe('192.0.2.1, 192.0.2.2, 192.0.2.3 (+2 more) · /24 · at most 4 routes');
    expect(summarizeHistoryLabel({ ...emptySummarizeForm(), addresses: '192.0.2.1' })).toBe('192.0.2.1');
  });

  it('fills fields a kept form lacks with their defaults', () => {
    const form = restoreSummarizeForm({ addresses: '192.0.2.1' } as ReturnType<typeof emptySummarizeForm>);
    expect(form).toEqual({ ...emptySummarizeForm(), addresses: '192.0.2.1' });
  });
});
