import type {
  AppgateBuildOptions,
  CatoBuildOptions,
  CloudProvider,
  FmcBuildOptions,
  MerakiBuildOptions,
  MerakiOrg,
  MerakiOrgInput,
  OpnsenseBuildOptions,
  OrgBuildOptions,
  PanoramaBuildOptions,
} from '@/api/meraki';

import {
  CATO_BASE_URL,
  DEFAULT_BASE_URL,
  FALLBACK_APPGATE_OPTIONS,
  FALLBACK_CATO_OPTIONS,
  FALLBACK_FMC_OPTIONS,
  FALLBACK_OPNSENSE_OPTIONS,
  FALLBACK_OPTIONS,
  FALLBACK_PANORAMA_OPTIONS,
} from './merakiHelpers';

/**
 * Flat form state of a topology source: `name`, `base_url`, `org_id` and the
 * write-only `secret`, plus every build option under its own key.
 */
export type SourceFormValues = Record<string, string | number | boolean>;

export interface RequiredRule {
  name: string;
  /** `'create'`: required only when adding (a blank secret on edit keeps the stored one). */
  required?: boolean | 'create';
}

/** Form keys of the scheduled collection, which are fields of the entry rather than build options. */
export const SCHEDULE_KEYS = ['auto_collect', 'collect_interval_minutes'] as const;

const COMMON_KEYS = ['name', 'base_url', 'org_id', 'secret', ...SCHEDULE_KEYS] as const;

function text(values: SourceFormValues, key: string): string {
  const v = values[key];
  return typeof v === 'string' ? v : v == null ? '' : String(v);
}

/** Starting values. The secret always opens blank since the API never returns it. */
function recordValues(
  existing: MerakiOrg | null,
  defaults: OrgBuildOptions,
  fallbackBaseUrl = '',
): SourceFormValues {
  // An entry saved before an option existed lacks its key; the defaults fill
  // it in so every toggle starts checked or unchecked, never blank.
  const options = { ...defaults, ...existing?.options } as Record<string, unknown>;
  const values: SourceFormValues = {};
  for (const [key, value] of Object.entries(options)) {
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') values[key] = value;
  }
  values.name = existing?.name ?? '';
  values.base_url = existing?.base_url ?? fallbackBaseUrl;
  values.org_id = existing?.org_id ?? '';
  values.secret = '';
  values.auto_collect = existing?.auto_collect ?? true;
  // The form edits minutes; 0 uses the global interval.
  values.collect_interval_minutes = Math.round((existing?.collect_interval_seconds ?? 0) / 60);
  return values;
}

function recordPayload(
  values: SourceFormValues,
  provider: CloudProvider | undefined,
  extraOptions: Record<string, unknown> = {},
): MerakiOrgInput {
  const options: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(values)) {
    if (!(COMMON_KEYS as readonly string[]).includes(key)) options[key] = value;
  }
  const body: MerakiOrgInput = {
    name: text(values, 'name').trim(),
    org_id: text(values, 'org_id').trim(),
    base_url: text(values, 'base_url').trim(),
    // The form holds exactly the provider's option keys (seeded from its
    // defaults), so the flat record is that provider's build options.
    options: { ...options, ...extraOptions } as unknown as OrgBuildOptions,
  };
  if (provider) body.provider = provider;
  body.auto_collect = values.auto_collect !== false;
  body.collect_interval_seconds = Math.max(0, Math.round(Number(values.collect_interval_minutes) || 0)) * 60;
  const secret = text(values, 'secret').trim();
  if (secret) body.api_key = secret;
  return body;
}

export const merakiForm = {
  fromRecord(existing: MerakiOrg | null, defaults: OrgBuildOptions): SourceFormValues {
    const values = recordValues(existing, defaults, DEFAULT_BASE_URL);
    const options = { ...defaults, ...existing?.options } as { network_tags?: unknown };
    values.network_tags = Array.isArray(options.network_tags) ? options.network_tags.join(', ') : '';
    return values;
  },
  // A Meraki organization is the default provider, so the body names none.
  toPayload(values: SourceFormValues): MerakiOrgInput {
    return recordPayload(values, undefined, {
      network_tags: text(values, 'network_tags')
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean),
    });
  },
};

export const catoForm = {
  fromRecord: (existing: MerakiOrg | null, defaults: OrgBuildOptions) =>
    recordValues(existing, defaults, CATO_BASE_URL),
  toPayload: (values: SourceFormValues) => recordPayload(values, 'cato'),
};

export const fmcForm = {
  fromRecord: (existing: MerakiOrg | null, defaults: OrgBuildOptions) => recordValues(existing, defaults),
  toPayload: (values: SourceFormValues) =>
    recordPayload(values, 'fmc', { username: text(values, 'username').trim() }),
};

export const panoramaForm = {
  fromRecord: (existing: MerakiOrg | null, defaults: OrgBuildOptions) => recordValues(existing, defaults),
  toPayload: (values: SourceFormValues) =>
    recordPayload(values, 'panorama', { username: text(values, 'username').trim() }),
};

export const appgateForm = {
  fromRecord(existing: MerakiOrg | null, defaults: OrgBuildOptions): SourceFormValues {
    const values = recordValues(existing, defaults);
    values.org_id = existing?.org_id || 'local';
    return values;
  },
  toPayload(values: SourceFormValues): MerakiOrgInput {
    const body = recordPayload(values, 'appgate', { username: text(values, 'username').trim() });
    body.org_id = body.org_id || 'local';
    return body;
  },
};

/** Form keys of the two halves of an OPNsense API credential, which are not build options. */
export const OPNSENSE_KEY_FIELD = 'opnsense_api_key';
export const OPNSENSE_SECRET_FIELD = 'opnsense_api_secret';

/**
 * The write-only secret of an OPNsense source from the two halves of its API
 * credential: `<key>:<secret>`, trimmed. Both blank keeps the stored credential
 * (`apiKey` null, no error); one half alone, or a colon in the key, is an error.
 */
export function joinOpnsenseCredential(key: string, secret: string): { apiKey: string | null; error: string | null } {
  const k = key.trim();
  const s = secret.trim();
  if (!k && !s) return { apiKey: null, error: null };
  if (!k || !s) return { apiKey: null, error: 'Enter both the API key and the API secret.' };
  if (k.includes(':')) return { apiKey: null, error: 'The API key cannot contain a colon.' };
  return { apiKey: `${k}:${s}`, error: null };
}

export const opnsenseForm = {
  fromRecord(existing: MerakiOrg | null, defaults: OrgBuildOptions): SourceFormValues {
    const values = recordValues(existing, defaults);
    values.org_id = existing?.org_id || 'local';
    values[OPNSENSE_KEY_FIELD] = '';
    values[OPNSENSE_SECRET_FIELD] = '';
    return values;
  },
  toPayload(values: SourceFormValues): MerakiOrgInput {
    const { apiKey } = joinOpnsenseCredential(text(values, OPNSENSE_KEY_FIELD), text(values, OPNSENSE_SECRET_FIELD));
    // The halves are not build options; the joined credential is the entry's secret.
    const rest: SourceFormValues = { ...values, secret: apiKey ?? '' };
    delete rest[OPNSENSE_KEY_FIELD];
    delete rest[OPNSENSE_SECRET_FIELD];
    const body = recordPayload(rest, 'opnsense');
    body.org_id = 'local';
    return body;
  },
  /**
   * Why the credential cannot be saved, or null. When adding, both halves are
   * required fields already, so a missing half is left to that check.
   */
  validate(values: SourceFormValues, isEdit: boolean): string | null {
    const key = text(values, OPNSENSE_KEY_FIELD).trim();
    const secret = text(values, OPNSENSE_SECRET_FIELD).trim();
    if (!isEdit && (!key || !secret)) return null;
    return joinOpnsenseCredential(key, secret).error;
  },
};

/** True when every required field has a non-blank value. */
export function isSourceFormReady(fields: readonly RequiredRule[], values: SourceFormValues, isEdit: boolean): boolean {
  return fields.every((f) => {
    if (!f.required || (f.required === 'create' && isEdit)) return true;
    return text(values, f.name).trim() !== '';
  });
}

/** The per-provider defaults the `/sources` listing reports. */
export interface SourceDefaults {
  default_options?: MerakiBuildOptions;
  cato_default_options?: CatoBuildOptions;
  fmc_default_options?: FmcBuildOptions;
  panorama_default_options?: PanoramaBuildOptions;
  appgate_default_options?: AppgateBuildOptions;
  opnsense_default_options?: OpnsenseBuildOptions;
}

/** The server's default build options for a provider, or the built-in fallback until they load. */
export function defaultOptionsFor(provider: CloudProvider, data: SourceDefaults | undefined): OrgBuildOptions {
  switch (provider) {
    case 'meraki':
      return data?.default_options ?? FALLBACK_OPTIONS;
    case 'cato':
      return data?.cato_default_options ?? FALLBACK_CATO_OPTIONS;
    case 'fmc':
      return data?.fmc_default_options ?? FALLBACK_FMC_OPTIONS;
    case 'panorama':
      return data?.panorama_default_options ?? FALLBACK_PANORAMA_OPTIONS;
    case 'appgate':
      return data?.appgate_default_options ?? FALLBACK_APPGATE_OPTIONS;
    case 'opnsense':
      return data?.opnsense_default_options ?? FALLBACK_OPNSENSE_OPTIONS;
  }
}
