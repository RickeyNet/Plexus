/**
 * Plugins: the `/api/plugins` manifest (what the caller may use, with each
 * plugin's sidebar entries and declarative pages) and the requests a plugin
 * page makes to its own API under `/api/plugins/<name>/`.
 *
 * The page contract is documented in docs/plugin-development.md and
 * validated server-side (netcontrol/plugins/base.py).
 */
import { useQuery } from '@tanstack/react-query';

import { apiRequest } from './client';

// ── Types ──────────────────────────────────────────────────────────────────

export type PluginStatus = 'disabled' | 'failed' | 'loaded' | 'active';

export interface PluginTextBlock {
  type: 'text';
  id: string;
  text: string;
}

export interface PluginTableColumn {
  key: string;
  label: string;
}

export interface PluginTableBlock {
  type: 'table';
  id: string;
  title: string;
  /** Path relative to the plugin API; GET returns a list (or `{items}`). */
  source: string;
  columns: PluginTableColumn[];
  empty_text: string;
}

export interface PluginFormField {
  name: string;
  label: string;
  type: 'text' | 'number' | 'textarea' | 'select' | 'checkbox';
  required: boolean;
  options: string[];
  help: string;
}

export interface PluginFormBlock {
  type: 'form';
  id: string;
  title: string;
  /** Path relative to the plugin API the fields are sent to as JSON. */
  submit: string;
  method: 'POST' | 'PUT';
  submit_label: string;
  fields: PluginFormField[];
  /** Table block ids on the same page to reload after a successful submit. */
  refreshes: string[];
}

export type PluginBlock = PluginTextBlock | PluginTableBlock | PluginFormBlock;

export interface PluginPageDef {
  id: string;
  title: string;
  description: string;
  blocks: PluginBlock[];
}

export interface PluginNavItem {
  label: string;
  page: string;
}

export interface PluginEntry {
  name: string;
  label: string;
  version: string;
  description: string;
  status: PluginStatus;
  /** The access-group feature key, `plugin:<name>`. */
  feature: string;
  navigation: PluginNavItem[];
  pages: PluginPageDef[];
  // Admin-only details.
  source?: string;
  min_plexus_version?: string | null;
  max_plexus_version?: string | null;
  errors?: string[];
  has_router?: boolean;
  migrations?: string | null;
  migrations_applied?: number;
  background_tasks?: number;
}

export interface PluginManifest {
  admin: boolean;
  plugins: PluginEntry[];
}

// ── Queries ────────────────────────────────────────────────────────────────

export const PLUGINS_QUERY_KEY = ['plugins', 'manifest'] as const;

/** The manifest. Plugins load at server start, so it changes only on restart. */
export function usePluginManifest(enabled = true) {
  return useQuery({
    queryKey: PLUGINS_QUERY_KEY,
    queryFn: () => apiRequest<PluginManifest>('/plugins'),
    staleTime: 5 * 60_000,
    enabled,
  });
}

/** The API path (after `/api`) of a plugin-relative data path. */
export function pluginApiPath(plugin: string, relative: string): string {
  return `/plugins/${encodeURIComponent(plugin)}/${relative}`;
}

/** The SPA route of a plugin page. */
export function pluginPageRoute(plugin: string, page: string): string {
  return `/plugins/${encodeURIComponent(plugin)}/${encodeURIComponent(page)}`;
}

export function pluginTableQueryKey(plugin: string, source: string) {
  return ['plugins', 'data', plugin, source] as const;
}

/** Rows of a table block: the response list, or its `items` list. */
export function tableRows(body: unknown): Record<string, unknown>[] {
  const list = Array.isArray(body)
    ? body
    : body && typeof body === 'object' && Array.isArray((body as { items?: unknown }).items)
      ? (body as { items: unknown[] }).items
      : [];
  return list.filter((r): r is Record<string, unknown> => !!r && typeof r === 'object' && !Array.isArray(r));
}

export function usePluginTable(plugin: string, source: string) {
  return useQuery({
    queryKey: pluginTableQueryKey(plugin, source),
    queryFn: async () => tableRows(await apiRequest<unknown>(pluginApiPath(plugin, source))),
  });
}

/** A cell as plain text: never HTML. Objects are shown as compact JSON. */
export function cellText(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (typeof value === 'object') {
    try {
      return JSON.stringify(value);
    } catch {
      return '';
    }
  }
  return String(value);
}

export type FormValues = Record<string, string | boolean>;

export function initialFormValues(fields: PluginFormField[]): FormValues {
  const out: FormValues = {};
  for (const f of fields) {
    if (f.type === 'checkbox') out[f.name] = false;
    else if (f.type === 'select') out[f.name] = f.required && f.options.length ? f.options[0] : '';
    else out[f.name] = '';
  }
  return out;
}

/**
 * The JSON body of a form: numbers as numbers (an empty number field is
 * left out so the plugin's default applies), checkboxes as booleans.
 * Returns the label of the first missing required field instead, if any.
 */
export function formBody(
  fields: PluginFormField[],
  values: FormValues,
): { body: Record<string, unknown> } | { missing: string } {
  const body: Record<string, unknown> = {};
  for (const f of fields) {
    const raw = values[f.name];
    if (f.type === 'checkbox') {
      body[f.name] = raw === true;
      continue;
    }
    const text = typeof raw === 'string' ? raw.trim() : '';
    if (!text) {
      if (f.required) return { missing: f.label };
      continue;
    }
    if (f.type === 'number') {
      const n = Number(text);
      if (!Number.isFinite(n)) return { missing: f.label };
      body[f.name] = n;
    } else {
      body[f.name] = text;
    }
  }
  return { body };
}

/** The source paths of the table blocks a form names in `refreshes`. */
export function refreshSources(form: PluginFormBlock, blocks: PluginBlock[]): string[] {
  const wanted = new Set(form.refreshes);
  return blocks.filter((b): b is PluginTableBlock => b.type === 'table' && wanted.has(b.id)).map((b) => b.source);
}

export function submitPluginForm(plugin: string, block: PluginFormBlock, body: Record<string, unknown>) {
  return apiRequest<unknown>(pluginApiPath(plugin, block.submit), { method: block.method, body });
}

/** Sidebar entries of the active plugins in a manifest. */
export function pluginNavEntries(manifest: PluginManifest | undefined): { key: string; label: string; to: string; feature: string }[] {
  if (!manifest) return [];
  return manifest.plugins
    .filter((p) => p.status === 'active')
    .flatMap((p) =>
      p.navigation.map((n) => ({
        key: `${p.name}/${n.page}`,
        label: n.label,
        to: pluginPageRoute(p.name, n.page),
        feature: p.feature,
      })),
    );
}
