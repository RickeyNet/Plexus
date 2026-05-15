import type { QueryClient } from '@tanstack/react-query';

import { streamPollNow, type PollNowEvent } from '@/api/monitoring';

export interface PollProgressLine {
  ok: boolean;
  hostname: string;
  detail: string;
}

export interface PollProgress {
  active: boolean;
  total: number;
  completed: number;
  title: string;
  failed: boolean;
  log: PollProgressLine[];
  startedAt: number | null;
}

const STORAGE_KEY = 'plexus.monitoring.pollProgress';
const FINISHED_TTL_MS = 60 * 60 * 1000;

const initial: PollProgress = {
  active: false,
  total: 0,
  completed: 0,
  title: '',
  failed: false,
  log: [],
  startedAt: null,
};

function loadFromStorage(): PollProgress {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return initial;
    const saved = JSON.parse(raw) as PollProgress;
    // Drop stale finished runs; let the next start clear things.
    if (!saved.active && saved.startedAt && Date.now() - saved.startedAt > FINISHED_TTL_MS) {
      return initial;
    }
    // A run marked "active" but with no live stream attached is a stale
    // page-reload artifact — the backend kept polling, but we can't reattach
    // to its SSE stream. Surface it as finished-unknown so the user sees
    // *something* instead of a spinner that never advances.
    if (saved.active) {
      return {
        ...saved,
        active: false,
        title: saved.title || 'Poll status unknown after reload — click Refresh',
      };
    }
    return saved;
  } catch {
    return initial;
  }
}

let state: PollProgress = loadFromStorage();
let abort: AbortController | null = null;
let queryClient: QueryClient | null = null;
const listeners = new Set<(s: PollProgress) => void>();

export function bindQueryClient(qc: QueryClient) {
  queryClient = qc;
}

function persist() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch { /* quota / disabled storage — ignore */ }
}

function emit() {
  persist();
  for (const fn of listeners) fn(state);
}

function setState(updater: (prev: PollProgress) => PollProgress) {
  state = updater(state);
  emit();
}

export function getPollProgress(): PollProgress {
  return state;
}

export function subscribePollProgress(fn: (s: PollProgress) => void): () => void {
  listeners.add(fn);
  return () => { listeners.delete(fn); };
}

export function isPollRunning(): boolean {
  return state.active && abort != null;
}

export function dismissPollProgress() {
  if (state.active) return;
  setState(() => ({ ...initial }));
}

export async function startPollNow(): Promise<void> {
  if (state.active && abort) return;

  abort?.abort();
  const controller = new AbortController();
  abort = controller;
  setState(() => ({
    ...initial,
    active: true,
    title: 'Starting poll…',
    startedAt: Date.now(),
  }));

  try {
    await streamPollNow((event: PollNowEvent) => {
      setState((prev) => {
        if (event.type === 'start') {
          return { ...prev, total: event.total_hosts ?? 0, title: `Polling ${event.total_hosts} device(s)…` };
        }
        if (event.type === 'host_done' || event.type === 'host_error') {
          const ok = event.type === 'host_done' && event.status === 'ok';
          const details: string[] = [];
          if (event.cpu != null) details.push(`CPU ${event.cpu}%`);
          if (event.memory != null) details.push(`Mem ${event.memory}%`);
          if (event.alerts && event.alerts > 0) details.push(`${event.alerts} alert${event.alerts !== 1 ? 's' : ''}`);
          const detail = event.type === 'host_error' ? 'error' : details.join(', ');
          return {
            ...prev,
            completed: event.completed ?? prev.completed,
            total: event.total_hosts ?? prev.total,
            log: [...prev.log, { ok, hostname: event.hostname ?? '', detail }],
          };
        }
        if (event.type === 'done') {
          return {
            ...prev,
            active: false,
            completed: prev.total,
            title: `Poll complete: ${event.hosts_polled} polled, ${event.alerts_created} alerts, ${event.errors} errors`,
          };
        }
        return prev;
      });
    }, controller.signal);
    setState((prev) => prev.active ? { ...prev, active: false } : prev);
    queryClient?.invalidateQueries({ queryKey: ['monitoring-polls'] });
    queryClient?.invalidateQueries({ queryKey: ['monitoring-summary'] });
    queryClient?.invalidateQueries({ queryKey: ['monitoring-alerts'] });
  } catch (e) {
    if (controller.signal.aborted) {
      return;
    }
    setState((prev) => ({
      ...prev,
      active: false,
      failed: true,
      title: `Poll failed: ${(e as Error).message}`,
    }));
  } finally {
    if (abort === controller) abort = null;
  }
}
