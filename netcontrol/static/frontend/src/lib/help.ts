import type { HelpSection } from '@/api/help';

/** Where a click on a link inside a help page goes. */
export type HelpLink =
  | { kind: 'page'; name: string; anchor: string }
  | { kind: 'anchor'; anchor: string }
  | { kind: 'other' };

/**
 * Classify a link's raw `href` attribute: another help page
 * (`/help/<page>#<anchor>`), a heading of this page (`#<anchor>`), or
 * anything else, which the browser follows as usual.
 */
export function helpLink(href: string | null): HelpLink {
  if (!href) return { kind: 'other' };
  if (href.startsWith('#')) return { kind: 'anchor', anchor: decodeURIComponent(href.slice(1)) };
  const match = /^\/help\/([^#?/]+)(?:#(.*))?$/.exec(href);
  if (!match) return { kind: 'other' };
  return { kind: 'page', name: decodeURIComponent(match[1]), anchor: match[2] ? decodeURIComponent(match[2]) : '' };
}

/** The sections, with only the pages whose title holds `text` (case-insensitive). */
export function filterSections(sections: HelpSection[], text: string): HelpSection[] {
  const needle = text.trim().toLowerCase();
  if (!needle) return sections;
  return sections
    .map((s) => ({ ...s, pages: s.pages.filter((p) => p.title.toLowerCase().includes(needle)) }))
    .filter((s) => s.pages.length > 0);
}
