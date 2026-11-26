import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import type { InventoryGroupFull } from '@/api/inventory';
import { READ_ONLY_GROUP_REASON } from '@/lib/objectScope';

import { GroupCard } from './Inventory';

const GROUP: InventoryGroupFull = {
  id: 4,
  name: 'site-a',
  parent_id: null,
  path: 'site-a',
  depth: 0,
  hosts: [{ id: 40, hostname: 'edge-a', ip_address: '192.0.2.10', device_type: 'cisco_ios' } as never],
};

const noop = () => {};

function render(canWrite: boolean, selected: number[] = []): string {
  return renderToStaticMarkup(
    <QueryClientProvider client={new QueryClient()}>
      <GroupCard
        group={GROUP}
        canWrite={canWrite}
        subGroupCount={0}
        query=""
        compact={false}
        collapsed={false}
        draggable={false}
        selectedSet={new Set(selected)}
        assignedProfileId=""
        snmpProfiles={[]}
        onAssignProfile={noop}
        onToggleCollapse={noop}
        onDragStart={noop}
        onDragOver={noop}
        onDrop={noop}
        onSelectionChange={noop}
        onEditGroup={noop}
        onAddSubGroup={noop}
        onDeleteGroup={noop}
        onSyncDiscovery={noop}
        onBulkSerial={noop}
        onAddHost={noop}
        onEditHost={noop}
        onDeleteHost={noop}
        onFetchSerial={noop}
        onBulkMove={noop}
        onBulkDelete={noop}
        onBulkTag={noop}
        onBulkEdit={noop}
        onBulkSnmpProfile={noop}
      />
    </QueryClientProvider>,
  );
}

/** The opening tag of the first button whose text is ``label``. */
function button(html: string, label: string): string {
  const m = new RegExp(`<button[^>]*>${label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}</button>`).exec(html);
  return m?.[0] ?? '';
}

describe('GroupCard rendering', () => {
  // The page hands every card stable callbacks and the debounced search, so
  // a keystroke re-renders only the page, not each group.
  it('is memoised', () => {
    expect((GroupCard as unknown as { $$typeof: symbol }).$$typeof).toBe(Symbol.for('react.memo'));
  });
});

describe('GroupCard write controls', () => {
  it('are enabled for a writable group', () => {
    const html = render(true, [40]);
    for (const label of ['Sync', '+ Add Host', 'Move', 'Tag…', 'Edit…', 'Set SNMP…']) {
      expect(button(html, label), label).not.toBe('');
      expect(button(html, label), label).not.toContain('disabled');
    }
    expect(html).not.toContain(READ_ONLY_GROUP_REASON);
  });

  it('are disabled with the reason for a read-only group', () => {
    const html = render(false, [40]);
    // (Host rows are virtualized and not rendered without a browser; their
    // Edit and Delete use the same readOnly flag.)
    for (const label of ['Sync', '+ Add Host', 'Move', 'Tag…', 'Edit…', 'Set SNMP…', 'Delete', 'Serial']) {
      const tag = button(html, label);
      expect(tag, label).toContain('disabled');
      expect(tag, label).toContain(`title="${READ_ONLY_GROUP_REASON}"`);
    }
    expect(html).toMatch(/<select[^>]*disabled=""[^>]*title="Read-only access to this inventory group"/);
    // Selecting hosts (reading) still works.
    expect(html).toMatch(/<input type="checkbox"(?![^>]*disabled)[^>]*aria-label="Select all hosts in site-a"/);
  });
});
