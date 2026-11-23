/**
 * Hardware components (chassis, modules, power supplies, fans, transceivers)
 * and their change history: labels, badge tones, the category order of the
 * device table, its filter, and the one-sentence description of a change.
 */
import type { Tone } from './severity';

export type HardwareCategory = 'chassis' | 'module' | 'power_supply' | 'fan' | 'transceiver' | 'other';
export type ComponentStatus = 'present' | 'missing' | 'removed';
export type HardwareEventType = 'baseline' | 'installed' | 'removed' | 'replaced' | 'moved' | 'changed';

/** Rows per server page on the Hardware page. */
export const HARDWARE_PAGE_SIZE = 100;

/** The categories in the order the device table lists them. */
export const HARDWARE_CATEGORIES: readonly { value: HardwareCategory; label: string }[] = [
  { value: 'chassis', label: 'Chassis' },
  { value: 'module', label: 'Modules' },
  { value: 'power_supply', label: 'Power supplies' },
  { value: 'fan', label: 'Fans' },
  { value: 'transceiver', label: 'Transceivers' },
  { value: 'other', label: 'Other' },
];

export const COMPONENT_STATUSES: readonly { value: ComponentStatus; label: string; tone: Tone }[] = [
  { value: 'present', label: 'Present', tone: 'success' },
  { value: 'missing', label: 'Missing', tone: 'warning' },
  { value: 'removed', label: 'Removed', tone: 'neutral' },
];

export const HARDWARE_EVENTS: readonly { value: HardwareEventType; label: string; tone: Tone }[] = [
  { value: 'replaced', label: 'Replaced', tone: 'warning' },
  { value: 'installed', label: 'Installed', tone: 'success' },
  { value: 'removed', label: 'Removed', tone: 'danger' },
  { value: 'moved', label: 'Moved', tone: 'info' },
  { value: 'changed', label: 'Changed', tone: 'info' },
  { value: 'baseline', label: 'First read', tone: 'neutral' },
];

export function categoryLabel(category: string): string {
  return HARDWARE_CATEGORIES.find((c) => c.value === category)?.label ?? (category || 'Other');
}

export function statusInfo(status: string): { label: string; tone: Tone } {
  return COMPONENT_STATUSES.find((s) => s.value === status) ?? { label: status || '-', tone: 'neutral' };
}

export function eventInfo(event: string): { label: string; tone: Tone } {
  return HARDWARE_EVENTS.find((e) => e.value === event) ?? { label: event || '-', tone: 'neutral' };
}

/** Where the category sorts in the device table; unknown categories go last. */
export function categoryRank(category: string): number {
  const i = HARDWARE_CATEGORIES.findIndex((c) => c.value === category);
  return i === -1 ? HARDWARE_CATEGORIES.length : i;
}

/** The fields of a component the device table filters and sorts on. */
export interface ComponentLike {
  category: string;
  slot: string;
  name: string;
  description: string;
  model: string;
  serial: string;
  status: string;
}

export interface ComponentFilter {
  category: HardwareCategory | '';
  text: string;
  showRemoved: boolean;
}

/**
 * The components the device table shows: removed ones only when asked for,
 * the category and text filter applied, ordered by category, then slot
 * (natural order, so slot 2 comes before slot 10), then name.
 */
export function visibleComponents<T extends ComponentLike>(components: readonly T[], filter: ComponentFilter): T[] {
  const needle = filter.text.trim().toLowerCase();
  return components
    .filter((c) => filter.showRemoved || c.status !== 'removed')
    .filter((c) => !filter.category || c.category === filter.category)
    .filter(
      (c) =>
        !needle ||
        [c.slot, c.name, c.description, c.model, c.serial].some((v) => (v || '').toLowerCase().includes(needle)),
    )
    .sort(
      (a, b) =>
        categoryRank(a.category) - categoryRank(b.category) ||
        SLOT_COLLATOR.compare(a.slot || '', b.slot || '') ||
        SLOT_COLLATOR.compare(a.name || '', b.name || ''),
    );
}

const SLOT_COLLATOR = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });

/**
 * The `event` parameter the fleet change feed sends: the picked type, or for
 * "All changes" every type but the first read (baseline), as the comma list
 * the server takes, so its paging and total count only what is shown.
 */
export function eventFilterParam(picked: HardwareEventType | ''): string {
  return (
    picked ||
    HARDWARE_EVENTS.filter((e) => e.value !== 'baseline')
      .map((e) => e.value)
      .join(',')
  );
}

// ── Change sentences ─────────────────────────────────────────────────────

/** The fields of an event the sentence reads. */
export interface HardwareEventLike {
  event: string;
  category: string;
  slot: string;
  name: string;
  model: string;
  serial: string;
  previous_serial: string;
  previous_model: string;
  previous_slot: string;
  previous_host_id: number | null;
  previous_hostname: string;
  changes: Record<string, { before: string; after: string }>;
  detail: string;
}

/** A piece of a change sentence: text, or another host (a link when its id is known). */
export type SentencePart = string | { hostId: number | null; hostname: string };

const FIELD_LABELS: Record<string, string> = {
  hardware_rev: 'Hardware revision',
  firmware_rev: 'Firmware revision',
  software_rev: 'Software revision',
  description: 'Description',
  name: 'Name',
  model: 'Model',
  serial: 'Serial',
  slot: 'Slot',
};

/** A changed field's name for people: `firmware_rev` reads "Firmware revision". */
export function fieldLabel(field: string): string {
  return FIELD_LABELS[field] ?? field.replace(/_/g, ' ').replace(/^./, (ch) => ch.toUpperCase());
}

/** "Slot 3" for a bare number, the slot as given otherwise ("Te1/0/1", "PS1"). */
function placeLabel(slot: string, name: string, category: string): string {
  if (slot) return /^\d+$/.test(slot) ? `Slot ${slot}` : slot;
  return name || categoryLabel(category);
}

/** "FOC0000X0AA (C9400-LC-48U)": the serial with the model, either may be missing. */
function partLabel(serial: string, model: string): string {
  if (serial && model) return `${serial} (${model})`;
  if (serial) return serial;
  if (model) return `${model} (no serial)`;
  return 'a part with no serial';
}

/**
 * One event as a sentence a person reads at a glance, in parts so the page
 * can link another host. Examples:
 * "Slot 3: FOC0000X0AA (C9400-LC-48U) replaced by FOC0000X0BB (C9400-LC-48U)",
 * "PS2: LIT0000A1 (PWR-C1-715WAC) installed, last seen on <edge-b>".
 */
export function hardwareEventParts(e: HardwareEventLike): SentencePart[] {
  const place = placeLabel(e.slot, e.name, e.category);
  const part = partLabel(e.serial, e.model);
  switch (e.event) {
    case 'baseline':
      return [e.detail || 'First hardware read of this device.'];
    case 'installed': {
      const parts: SentencePart[] = [`${place}: ${part} installed`];
      if (e.previous_hostname || e.previous_host_id !== null) {
        parts.push(', last seen on ', {
          hostId: e.previous_host_id,
          hostname: e.previous_hostname || `host ${e.previous_host_id}`,
        });
      }
      return parts;
    }
    case 'removed':
      return [`${place}: ${part} removed`];
    case 'replaced':
      return [`${place}: ${partLabel(e.previous_serial, e.previous_model)} replaced by ${part}`];
    case 'moved': {
      const from = e.previous_slot ? placeLabel(e.previous_slot, '', e.category) : 'another slot';
      return [`${part} moved from ${from} to ${place}`];
    }
    case 'changed': {
      const fields = Object.entries(e.changes ?? {}).map(
        ([field, c]) => `${fieldLabel(field)} ${c.before || '(empty)'} → ${c.after || '(empty)'}`,
      );
      return [`${place}: ${part} changed${fields.length ? `: ${fields.join('; ')}` : ''}`];
    }
    default:
      return [e.detail || `${place}: ${part} ${e.event}`];
  }
}

/** The event's sentence as plain text (another host by name). */
export function hardwareEventText(e: HardwareEventLike): string {
  return hardwareEventParts(e)
    .map((p) => (typeof p === 'string' ? p : p.hostname))
    .join('');
}
