// The history of Path Mode, the Reachability sweep and Summarize: what each
// records and how a recorded run is opened again. The server keeps each
// user's last 30 of each (routes/tool_history).

import type { NodeId, PathPick } from './paths';
import { emptySummarizeForm, type SummarizeForm } from './summarizeHelpers';
import { emptyFilters, emptyForm, type ReachabilityForm, type SweepEnd } from './sweep';

// ── Path Mode ───────────────────────────────────────────────────────────────

/** A path trace as kept: the picks in order and the traffic text. */
export interface PathHistoryData {
  picks: PathPick[];
  /** As typed (`tcp/443`), empty for any traffic. */
  traffic: string;
}

/** How long the picks must stay put before the trace is recorded, so the steps of building one are not each kept. */
export const HISTORY_SETTLE_MS = 2000;

/** Whether the picks make a trace worth keeping: two or more ends. */
export function historyWorthy(picks: PathPick[]): boolean {
  return picks.length >= 2;
}

/** What makes two traces the same: the picks' keys in order and the traffic (not the subnet records they carry). */
export function pathHistoryKey(data: PathHistoryData): string {
  return JSON.stringify([data.picks.map((p) => p.key), data.traffic.trim().toLowerCase()]);
}

/** A trace as one line: its ends in order and, when given, the traffic. */
export function pathHistoryLabel(data: PathHistoryData): string {
  const ends = (data.picks ?? []).map((p) => p.label).join(' → ');
  return data.traffic ? `${ends} · ${data.traffic}` : ends;
}

/**
 * The picks of a recorded trace that can be opened on the map as it is now:
 * a pick on a device that is no longer on the map is left out and named in
 * `dropped`. An internet application has no device and is always kept.
 */
export function restorePicks(picks: PathPick[], onMap: (node: NodeId) => boolean): { picks: PathPick[]; dropped: string[] } {
  const kept: PathPick[] = [];
  const dropped: string[] = [];
  for (const pick of picks) {
    if (pick.node === undefined || onMap(pick.node)) kept.push(pick);
    else dropped.push(pick.label);
  }
  return { picks: kept, dropped };
}

/** The note shown when some ends of a reopened trace are gone from the map. */
export function droppedNote(dropped: string[]): string {
  if (!dropped.length) return '';
  const names = dropped.join(', ');
  return dropped.length === 1
    ? `${names} is no longer on the map, so it was left out of the trace.`
    : `${names} are no longer on the map, so they were left out of the trace.`;
}

// ── Reachability sweep ──────────────────────────────────────────────────────

/** A sweep as kept: its form and the owner picked for each typed end. */
export interface ReachabilityHistoryData {
  form: ReachabilityForm;
  picked: Record<SweepEnd, string>;
}

/** A sweep as one line: source → destination (or "filtered networks") and the traffic. */
export function reachabilityHistoryLabel(data: ReachabilityHistoryData): string {
  const form = data.form ?? emptyForm();
  const source = form.source?.trim() || 'source networks';
  const destination = form.destination?.trim() || 'destination networks';
  return `${source} → ${destination} · ${form.traffic?.trim() || 'any traffic'}`;
}

/** A kept sweep's form, with any field a later version added filled with its default. */
export function restoreReachabilityForm(data: ReachabilityHistoryData): ReachabilityForm {
  const base = emptyForm();
  const saved = data.form ?? base;
  return { ...base, ...saved, to: { ...emptyFilters(), ...(saved.to ?? {}) } };
}

// ── Summarize ───────────────────────────────────────────────────────────────

const LABEL_ADDRESSES = 3;

/** A summary as one line: its first addresses, how many more, the roll-up and the route cap. */
export function summarizeHistoryLabel(form: SummarizeForm): string {
  const all = (form.addresses ?? '').split(/[\s,;]+/).filter(Boolean);
  const shown = all.slice(0, LABEL_ADDRESSES).join(', ');
  const parts = [all.length > LABEL_ADDRESSES ? `${shown} (+${all.length - LABEL_ADDRESSES} more)` : shown];
  if (form.prefix?.trim()) parts.push(`/${form.prefix.trim()}`);
  if (form.maxRoutes?.trim()) parts.push(`at most ${form.maxRoutes.trim()} routes`);
  return parts.join(' · ');
}

/** A kept summary's form, with any field a later version added filled with its default. */
export function restoreSummarizeForm(form: SummarizeForm): SummarizeForm {
  return { ...emptySummarizeForm(), ...form };
}
