import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import type { TagWithUsage } from '@/api/customData';
import { tagPickerOptions, toggleTag } from '@/lib/customData';

import { TagPicker } from './TagPicker';

const usage = { host: 0, group: 0, prefix: 0 };
const TAGS: TagWithUsage[] = [
  { id: 1, name: 'core', color: 'blue', description: '', usage },
  { id: 2, name: 'edge', color: 'green', description: '', usage },
  { id: 3, name: 'pci-scope', color: 'red', description: '', usage },
];

function render(value: number[], canCreate = true): string {
  const qc = new QueryClient();
  qc.setQueryData(['custom-data', 'tags'], TAGS);
  return renderToStaticMarkup(
    <QueryClientProvider client={qc}>
      <TagPicker value={value} onChange={() => {}} canCreate={canCreate} label="Add tags" />
    </QueryClientProvider>,
  );
}

describe('TagPicker', () => {
  it('offers Create only when nothing matches and canCreate', () => {
    // No tag is named "lab": offered.
    expect(tagPickerOptions(TAGS, [], 'lab', true).createName).toBe('lab');
    // A tag of that name exists, in any case: not offered, the tag is listed instead.
    const existing = tagPickerOptions(TAGS, [], 'CORE', true);
    expect(existing.createName).toBeNull();
    expect(existing.matches.map((t) => t.name)).toEqual(['core']);
    // Already selected still counts as existing.
    expect(tagPickerOptions(TAGS, [1], 'core', true)).toEqual({ matches: [], createName: null });
    // Not allowed to create, or nothing typed, or too long: not offered.
    expect(tagPickerOptions(TAGS, [], 'lab', false).createName).toBeNull();
    expect(tagPickerOptions(TAGS, [], '   ', true).createName).toBeNull();
    expect(tagPickerOptions(TAGS, [], 'x'.repeat(51), true).createName).toBeNull();
  });

  it('lists the unselected tags that contain the typed text', () => {
    expect(tagPickerOptions(TAGS, [2], '', true).matches.map((t) => t.id)).toEqual([1, 3]);
    expect(tagPickerOptions(TAGS, [], 'E', true).matches.map((t) => t.name)).toEqual(['core', 'edge', 'pci-scope']);
  });

  it('adds and removes a tag', () => {
    expect(toggleTag([1], 3)).toEqual([1, 3]);
    expect(toggleTag([1, 3], 1)).toEqual([3]);

    const html = render([1, 3]);
    expect(html).toContain('Add tags</label>');
    expect(html).toContain('aria-label="Remove tag core"');
    expect(html).toContain('aria-label="Remove tag pci-scope"');
    expect(html).not.toContain('Remove tag edge');
    expect(html).toContain('tag-chip-blue');
    expect(html).toContain('role="combobox"');
  });

  it('names a selected tag that no longer exists so it can be removed', () => {
    expect(render([99])).toContain('aria-label="Remove tag Deleted tag #99"');
  });

  it('hints at creating only when the user may', () => {
    expect(render([], true)).toContain('placeholder="Find or create a tag"');
    expect(render([], false)).toContain('placeholder="Find a tag"');
  });
});
