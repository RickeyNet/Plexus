import { describe, expect, it } from 'vitest';

import {
  categoryRank,
  eventFilterParam,
  fieldLabel,
  type HardwareEventLike,
  hardwareEventParts,
  hardwareEventText,
  visibleComponents,
} from './hardware';

// Invented components and events in the shape of the /api/hosts/{id}/hardware answers.
function event(over: Partial<HardwareEventLike>): HardwareEventLike {
  return {
    event: 'installed',
    category: 'module',
    slot: '3',
    name: 'Linecard(slot 3)',
    model: 'C9400-LC-48U',
    serial: 'FOC0000X0BB',
    previous_serial: '',
    previous_model: '',
    previous_slot: '',
    previous_host_id: null,
    previous_hostname: '',
    changes: {},
    detail: '',
    ...over,
  };
}

describe('hardwareEventText', () => {
  it('reads a replacement as old part replaced by new part', () => {
    const e = event({ event: 'replaced', previous_serial: 'FOC0000X0AA', previous_model: 'C9400-LC-48U' });
    expect(hardwareEventText(e)).toBe('Slot 3: FOC0000X0AA (C9400-LC-48U) replaced by FOC0000X0BB (C9400-LC-48U)');
  });

  it('reads an install, a removal and a move', () => {
    expect(hardwareEventText(event({}))).toBe('Slot 3: FOC0000X0BB (C9400-LC-48U) installed');
    expect(hardwareEventText(event({ event: 'removed' }))).toBe('Slot 3: FOC0000X0BB (C9400-LC-48U) removed');
    expect(hardwareEventText(event({ event: 'moved', slot: '5', previous_slot: '3' }))).toBe(
      'FOC0000X0BB (C9400-LC-48U) moved from Slot 3 to Slot 5',
    );
    expect(hardwareEventText(event({ event: 'moved', previous_slot: '' }))).toBe(
      'FOC0000X0BB (C9400-LC-48U) moved from another slot to Slot 3',
    );
  });

  it('keeps a named slot as given and falls back to the name, then the category', () => {
    expect(hardwareEventText(event({ category: 'transceiver', slot: 'Te1/0/1', model: '', serial: 'AGM0000A1' }))).toBe(
      'Te1/0/1: AGM0000A1 installed',
    );
    expect(hardwareEventText(event({ event: 'removed', slot: '', name: 'PS2', serial: '', model: 'PWR-C1-715WAC' }))).toBe(
      'PS2: PWR-C1-715WAC (no serial) removed',
    );
    expect(hardwareEventText(event({ event: 'removed', slot: '', name: '', category: 'fan', serial: '', model: '' }))).toBe(
      'Fans: a part with no serial removed',
    );
  });

  it('lists each changed field before and after', () => {
    const e = event({
      event: 'changed',
      changes: {
        firmware_rev: { before: '17.9.4', after: '17.12.1' },
        hardware_rev: { before: '', after: 'V02' },
      },
    });
    expect(hardwareEventText(e)).toBe(
      'Slot 3: FOC0000X0BB (C9400-LC-48U) changed: Firmware revision 17.9.4 → 17.12.1; Hardware revision (empty) → V02',
    );
    expect(hardwareEventText(event({ event: 'changed' }))).toBe('Slot 3: FOC0000X0BB (C9400-LC-48U) changed');
  });

  it('uses the server sentence for the first read', () => {
    expect(hardwareEventText(event({ event: 'baseline', detail: 'First hardware read: 14 components.' }))).toBe(
      'First hardware read: 14 components.',
    );
    expect(hardwareEventText(event({ event: 'baseline' }))).toBe('First hardware read of this device.');
  });

  it('uses the server sentence for an event type it does not know', () => {
    expect(hardwareEventText(event({ event: 'renamed', detail: 'Something else happened.' }))).toBe(
      'Something else happened.',
    );
  });
});

describe('hardwareEventParts', () => {
  it('names the host an installed part was last seen on, linkable when its id is known', () => {
    const parts = hardwareEventParts(event({ previous_host_id: 12, previous_hostname: 'edge-b' }));
    expect(parts).toEqual([
      'Slot 3: FOC0000X0BB (C9400-LC-48U) installed',
      ', last seen on ',
      { hostId: 12, hostname: 'edge-b' },
    ]);
    expect(hardwareEventText(event({ previous_host_id: 12, previous_hostname: 'edge-b' }))).toBe(
      'Slot 3: FOC0000X0BB (C9400-LC-48U) installed, last seen on edge-b',
    );
  });

  it('keeps a deleted host as plain text', () => {
    const parts = hardwareEventParts(event({ previous_host_id: null, previous_hostname: 'old-core' }));
    expect(parts[2]).toEqual({ hostId: null, hostname: 'old-core' });
  });

  it('adds nothing for an install with no earlier host', () => {
    expect(hardwareEventParts(event({}))).toHaveLength(1);
  });
});

describe('fieldLabel', () => {
  it('names the known fields and capitalises the others', () => {
    expect(fieldLabel('software_rev')).toBe('Software revision');
    expect(fieldLabel('vendor_type')).toBe('Vendor type');
  });
});

describe('visibleComponents', () => {
  const base = { name: '', description: '', model: '', serial: '', status: 'present' };
  const rows = [
    { ...base, category: 'transceiver', slot: 'Te1/0/2', serial: 'AGM0000A2' },
    { ...base, category: 'module', slot: '10', model: 'C9400-LC-24XS' },
    { ...base, category: 'module', slot: '2', model: 'C9400-LC-48U', status: 'missing' },
    { ...base, category: 'chassis', slot: '', model: 'C9407R' },
    { ...base, category: 'power_supply', slot: 'PS1', status: 'removed' },
  ];

  it('orders by category, then slot in natural order, and hides removed parts', () => {
    const out = visibleComponents(rows, { category: '', text: '', showRemoved: false });
    expect(out.map((r) => `${r.category}:${r.slot}`)).toEqual(['chassis:', 'module:2', 'module:10', 'transceiver:Te1/0/2']);
  });

  it('shows removed parts when asked', () => {
    const out = visibleComponents(rows, { category: '', text: '', showRemoved: true });
    expect(out.map((r) => r.category)).toContain('power_supply');
  });

  it('filters by category and text', () => {
    expect(visibleComponents(rows, { category: 'module', text: '', showRemoved: false })).toHaveLength(2);
    expect(visibleComponents(rows, { category: '', text: 'agm0000', showRemoved: false })).toHaveLength(1);
    expect(visibleComponents(rows, { category: '', text: '48u', showRemoved: false })[0].slot).toBe('2');
  });

  it('ranks an unknown category last', () => {
    expect(categoryRank('chassis')).toBe(0);
    expect(categoryRank('mystery')).toBeGreaterThan(categoryRank('other'));
  });
});

describe('eventFilterParam', () => {
  it('asks for every change but the first reads under All changes', () => {
    expect(eventFilterParam('')).toBe('replaced,installed,removed,moved,changed');
  });

  it('asks for the picked type alone, the first read included', () => {
    expect(eventFilterParam('baseline')).toBe('baseline');
    expect(eventFilterParam('replaced')).toBe('replaced');
  });
});
