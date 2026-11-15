import type { ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import type { InventoryGroupFull } from '@/api/inventory';
import { DialogContext } from '@/components/DialogProvider-context';
import type { AccessGroup } from '@/api/settings';

import { AccessGroupModal } from './AccessGroupModal';
import { AccessGroupsTab } from './AccessGroupsTab';
import { choicesFromGrants, grantsFromChoices, scopePayload, scopeSummary } from './accessGroupScope';

// The real Modal portals into document.body, which the node test environment
// has none of; render its title, body and footer in place instead.
vi.mock('@/components/Modal', () => ({
  Modal: ({ title, children, footer }: { title?: string; children: ReactNode; footer?: ReactNode }) => (
    <div role="dialog">
      <h3>{title}</h3>
      {children}
      <div className="modal-footer">{footer}</div>
    </div>
  ),
}));

const INVENTORY: InventoryGroupFull[] = [
  { id: 1, name: 'site-a', parent_id: null, path: 'site-a', depth: 0 },
  { id: 2, name: 'floor-1', parent_id: 1, path: 'site-a / floor-1', depth: 1 },
  { id: 3, name: 'site-b', parent_id: null, path: 'site-b', depth: 0 },
];

const SCOPED: AccessGroup = {
  id: 9,
  name: 'East operators',
  description: '',
  feature_keys: ['inventory'],
  member_count: 2,
  object_scope: 'groups',
  inventory_scopes: [
    { inventory_group_id: 2, can_write: true },
    { inventory_group_id: 3, can_write: false },
  ],
};

const EVERYTHING: AccessGroup = {
  id: 10,
  name: 'NOC',
  description: '',
  feature_keys: ['inventory'],
  object_scope: 'all',
  inventory_scopes: [],
};

function client(): QueryClient {
  const qc = new QueryClient();
  qc.setQueryData(['inventory-groups-full', false], INVENTORY);
  qc.setQueryData(['admin', 'access-groups'], [SCOPED, EVERYTHING]);
  return qc;
}

function renderModal(group: AccessGroup | null): string {
  return renderToStaticMarkup(
    <QueryClientProvider client={client()}>
      {group ? (
        <AccessGroupModal mode="edit" group={group} features={['inventory', 'inventory.write']} onClose={() => {}} />
      ) : (
        <AccessGroupModal mode="create" features={['inventory', 'inventory.write']} onClose={() => {}} />
      )}
    </QueryClientProvider>,
  );
}

describe('accessGroupScope helpers', () => {
  it('turns grants into choices and back', () => {
    const choices = choicesFromGrants(SCOPED.inventory_scopes);
    expect(choices.get(2)).toBe('write');
    expect(choices.get(3)).toBe('read');
    choices.set(1, 'none');
    expect(grantsFromChoices(choices)).toEqual([
      { inventory_group_id: 2, can_write: true },
      { inventory_group_id: 3, can_write: false },
    ]);
  });

  it('sends no grants for all devices', () => {
    const choices = choicesFromGrants(SCOPED.inventory_scopes);
    expect(scopePayload('all', choices)).toEqual({ object_scope: 'all', inventory_scopes: [] });
    expect(scopePayload('groups', choices).inventory_scopes).toHaveLength(2);
  });

  it('summarises the scope for the table', () => {
    const names = new Map([
      [2, 'site-a / floor-1'],
      [3, 'site-b'],
    ]);
    expect(scopeSummary(EVERYTHING, names)).toBe('All devices');
    expect(scopeSummary({ object_scope: 'groups', inventory_scopes: [] }, names)).toContain('No devices');
    expect(scopeSummary(SCOPED, names)).toBe(
      'Selected inventory groups: site-a / floor-1 (read and write), site-b (read)',
    );
    expect(scopeSummary({ object_scope: 'groups', inventory_scopes: [{ inventory_group_id: 44, can_write: false }] }, names)).toContain(
      'Group 44',
    );
  });
});

describe('AccessGroupModal', () => {
  it('offers the device access choice, all devices by default', () => {
    const html = renderModal(null);
    expect(html).toContain('Device access');
    expect(html).toMatch(/aria-checked="true"[^>]*>All devices</);
    // The inventory group tree shows only for selected groups.
    expect(html).not.toContain('Access to site-a');
  });

  it('shows the inventory group tree with each grant for a scoped group', () => {
    const html = renderModal(SCOPED);
    expect(html).toMatch(/aria-checked="true"[^>]*>Selected inventory groups</);
    expect(html).toContain('aria-label="Access to site-a"');
    expect(html).toContain('aria-label="Access to site-a / floor-1"');
    // floor-1 is read and write, site-b read, site-a no access.
    expect(html).toMatch(/aria-label="Access to site-a \/ floor-1"[^>]*>(?:(?!<\/select>).)*value="write" selected=""/s);
    expect(html).toMatch(/aria-label="Access to site-b"[^>]*>(?:(?!<\/select>).)*value="read" selected=""/s);
    expect(html).toMatch(/aria-label="Access to site-a"[^>]*>(?:(?!<\/select>).)*value="none" selected=""/s);
    // Sub-groups are indented under their parent.
    expect(html).toContain('padding-left:1.25rem');
    // The note names the pages scoped accounts can use.
    expect(html).toContain('these pages only: Inventory');
  });
});

describe('AccessGroupsTab', () => {
  it('shows each group\'s device access', () => {
    const html = renderToStaticMarkup(
      <QueryClientProvider client={client()}>
        <DialogContext.Provider value={{ confirm: async () => false, alert: async () => {} }}>
          <AccessGroupsTab capabilities={{ feature_flags: ['inventory'] } as never} />
        </DialogContext.Provider>
      </QueryClientProvider>,
    );
    expect(html).toContain('Devices: Selected inventory groups: site-a / floor-1 (read and write), site-b (read)');
    expect(html).toContain('Devices: All devices');
  });
});
