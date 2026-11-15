import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { InventoryGroupFull } from '@/api/inventory';
import { TOP_LEVEL_GROUP_REASON } from '@/lib/objectScope';

import { BulkMoveModal } from './BulkMoveModal';
import { GroupModal } from './GroupModal';

// site-a (4) is read only, site-b (5) and site-c (6) are writable.
const state = vi.hoisted(() => ({
  scope: { restricted: true, write_group_ids: [5, 6] } as { restricted: boolean; write_group_ids: number[] },
}));

vi.mock('@/api/auth', () => ({ useAuthStatus: () => ({ data: { role: 'user', object_scope: state.scope } }) }));
// The real Modal portals into document.body; render it in place.
vi.mock('@/components/Modal', () => ({
  Modal: ({ title, children, footer }: { title?: string; children: ReactNode; footer?: ReactNode }) => (
    <div role="dialog">
      <h3>{title}</h3>
      {children}
      <div className="modal-footer">{footer}</div>
    </div>
  ),
}));

const group = (id: number, name: string): InventoryGroupFull => ({
  id,
  name,
  parent_id: null,
  path: name,
  depth: 0,
  hosts: [],
});
const GROUPS = [group(4, 'site-a'), group(5, 'site-b'), group(6, 'site-c')];

function render(node: ReactNode): string {
  return renderToStaticMarkup(<QueryClientProvider client={new QueryClient()}>{node}</QueryClientProvider>);
}

/** The ids of the ``<option>``s of the select with ``id``. */
function options(html: string, id: string): string[] {
  const select = new RegExp(`<select[^>]*id="${id}"[^>]*>(.*?)</select>`).exec(html)?.[1] ?? '';
  return [...select.matchAll(/<option[^>]*value="(\d*)"/g)].map((m) => m[1]);
}

beforeEach(() => {
  state.scope = { restricted: true, write_group_ids: [5, 6] };
});

describe('Inventory target group pickers', () => {
  it('Move offers only writable groups other than the source', () => {
    const html = render(<BulkMoveModal hostIds={[1]} sourceGroupId={5} groups={GROUPS} onClose={() => {}} />);
    expect(html).toContain('site-c');
    expect(html).not.toContain('site-a');
    expect(html).not.toContain('>site-b<');
  });

  it('a new sub-group goes under a writable group, never the top level', () => {
    const html = render(<GroupModal group={null} isCreate groups={GROUPS} defaultParentId={5} onClose={() => {}} />);
    expect(options(html, 'inventory-group-parent')).toEqual(['', '5', '6']);
    expect(html).toContain(`title="${TOP_LEVEL_GROUP_REASON}"`);
    expect(html).toMatch(/<option value="" disabled=""/);
  });

  it('an unrestricted account sees every group and may pick the top level', () => {
    state.scope = { restricted: false, write_group_ids: [] };
    const move = render(<BulkMoveModal hostIds={[1]} sourceGroupId={5} groups={GROUPS} onClose={() => {}} />);
    expect(move).toContain('site-a');
    const html = render(<GroupModal group={null} isCreate groups={GROUPS} onClose={() => {}} />);
    expect(options(html, 'inventory-group-parent')).toEqual(['', '4', '5', '6']);
    expect(html).not.toContain(TOP_LEVEL_GROUP_REASON);
  });
});
