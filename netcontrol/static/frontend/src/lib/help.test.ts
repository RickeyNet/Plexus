import { describe, expect, it } from 'vitest';

import { filterSections, helpLink } from './help';

describe('helpLink', () => {
  it('reads a link to another help page, with or without a heading', () => {
    expect(helpLink('/help/Path-Trace')).toEqual({ kind: 'page', name: 'Path-Trace', anchor: '' });
    expect(helpLink('/help/Cato-Topology#search-and-path-mode')).toEqual({
      kind: 'page',
      name: 'Cato-Topology',
      anchor: 'search-and-path-mode',
    });
  });

  it('reads an in-page heading link', () => {
    expect(helpLink('#reading-a-trace')).toEqual({ kind: 'anchor', anchor: 'reading-a-trace' });
  });

  it('leaves outside links, other app paths and missing hrefs to the browser', () => {
    expect(helpLink('https://github.com/example/repo/blob/main/x.py')).toEqual({ kind: 'other' });
    expect(helpLink('/inventory')).toEqual({ kind: 'other' });
    expect(helpLink('/help/a/b')).toEqual({ kind: 'other' });
    expect(helpLink(null)).toEqual({ kind: 'other' });
  });
});

describe('filterSections', () => {
  const sections = [
    { title: 'Topology', pages: [{ name: 'Path-Trace', title: 'Path Trace' }, { name: 'AWS-Topology', title: 'AWS Topology' }] },
    { title: 'Monitoring', pages: [{ name: 'Monitoring', title: 'Monitoring' }] },
  ];

  it('keeps every section for an empty filter', () => {
    expect(filterSections(sections, '  ')).toBe(sections);
  });

  it('keeps matching pages and drops sections left empty', () => {
    expect(filterSections(sections, 'trace')).toEqual([{ title: 'Topology', pages: [{ name: 'Path-Trace', title: 'Path Trace' }] }]);
    expect(filterSections(sections, 'zzz')).toEqual([]);
  });
});
