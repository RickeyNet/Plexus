import type {
  AppgateBuildOptions,
  CatoBuildOptions,
  CloudProvider,
  FmcBuildOptions,
  MerakiBuildOptions,
  MerakiOrg,
  MerakiOrgInput,
  OrgBuildOptions,
  PanoramaBuildOptions,
} from '@/api/meraki';

import {
  CATO_BASE_URL,
  DEFAULT_BASE_URL,
  FALLBACK_APPGATE_OPTIONS,
  FALLBACK_CATO_OPTIONS,
  FALLBACK_FMC_OPTIONS,
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

const COMMON_KEYS = ['name', 'base_url', 'org_id', 'secret'] as const;

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

/** True when every required field has a non-blank value. */
export function isSourceFormReady(fields: readonly RequiredRule[], values: SourceFormValues, isEdit: boolean): boolean {
  return fields.every((f) => {
    if (!f.required || (f.required === 'create' && isEdit)) return true;
    return text(values, f.name).trim() !== '';
  });
}

/** The per-provider defaults the `/meraki/orgs` listing reports. */
export interface SourceDefaults {
  default_options?: MerakiBuildOptions;
  cato_default_options?: CatoBuildOptions;
  fmc_default_options?: FmcBuildOptions;
  panorama_default_options?: PanoramaBuildOptions;
  appgate_default_options?: AppgateBuildOptions;
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
  }
}
