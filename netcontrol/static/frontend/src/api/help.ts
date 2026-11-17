/**
 * Help under /api/help: the user guides (the same pages as the GitHub wiki),
 * their sections, full-text search, and one page rendered to HTML on the
 * server with any HTML in the source escaped.
 */
import { keepPreviousData, useQuery } from '@tanstack/react-query';

import { apiRequest, queryString } from './client';

export interface HelpPageRef {
  name: string;
  title: string;
}

export interface HelpSection {
  title: string;
  pages: HelpPageRef[];
}

export interface HelpIndex {
  home: string;
  sections: HelpSection[];
}

export interface HelpHeading {
  id: string;
  text: string;
  level: 2 | 3;
}

export interface HelpPage {
  name: string;
  title: string;
  section: string;
  source: string;
  source_url: string;
  headings: HelpHeading[];
  html: string;
}

export interface HelpSearchResult {
  name: string;
  title: string;
  section: string;
  snippet: string;
}

// The guides only change with an upgrade, so a read is good for the session.
const STALE = Infinity;

export function useHelpIndex() {
  return useQuery({
    queryKey: ['help', 'index'],
    queryFn: () => apiRequest<HelpIndex>('/help'),
    staleTime: STALE,
  });
}

export function useHelpPage(name: string) {
  return useQuery({
    queryKey: ['help', 'page', name],
    queryFn: () => apiRequest<HelpPage>(`/help/pages/${encodeURIComponent(name)}`),
    staleTime: STALE,
    enabled: name !== '',
  });
}

export function useHelpSearch(q: string) {
  const query = q.trim();
  return useQuery({
    queryKey: ['help', 'search', query],
    queryFn: () => apiRequest<{ query: string; results: HelpSearchResult[] }>(`/help/search${queryString({ q: query })}`),
    staleTime: STALE,
    enabled: query.length >= 2,
    placeholderData: keepPreviousData,
  });
}
