import type { ReactNode } from 'react';

import type { CloudProvider, MerakiOrg, MerakiOrgInput, OrgBuildOptions } from '@/api/meraki';

import {
  APPGATE_OPTION_TOGGLES,
  APPGATE_URL_PLACEHOLDER,
  CATO_BASE_URL,
  CATO_OPTION_TOGGLES,
  DEFAULT_BASE_URL,
  FMC_OPTION_TOGGLES,
  FMC_URL_PLACEHOLDER,
  OPTION_TOGGLES,
  PANORAMA_OPTION_TOGGLES,
  PANORAMA_URL_PLACEHOLDER,
} from './merakiHelpers';
import {
  appgateForm,
  catoForm,
  fmcForm,
  merakiForm,
  panoramaForm,
  type RequiredRule,
  type SourceFormValues,
} from './sourceForm';

export interface SourceField extends RequiredRule {
  label: string;
  type?: 'text' | 'password' | 'number' | 'checkbox' | 'url';
  placeholder?: string;
  /** Muted line under the input; for a checkbox, the line under its label. */
  help?: ReactNode;
  autoComplete?: string;
  min?: number;
  max?: number;
}

export type SourceFormBlock =
  | { kind: 'fields'; fields: SourceField[]; columns?: 1 | 2; maxWidth?: number }
  | { kind: 'heading'; text: string }
  /** A muted paragraph. */
  | { kind: 'note'; content: ReactNode }
  /** Rendered as given. */
  | { kind: 'node'; content: ReactNode };

export interface SourceFormConfig {
  /** "Add <noun>" / "Edit <noun>". */
  noun: string;
  /** Label of the submit button when adding. */
  addLabel: string;
  /** Prefix of the input ids. */
  idPrefix: string;
  blocks: SourceFormBlock[];
  fromRecord: (existing: MerakiOrg | null, defaults: OrgBuildOptions) => SourceFormValues;
  toPayload: (values: SourceFormValues) => MerakiOrgInput;
}

function toggleFields(toggles: readonly { key: string; label: string; hint: string }[]): SourceFormBlock {
  return {
    kind: 'fields',
    fields: toggles.map((t) => ({ name: t.key, label: t.label, help: t.hint, type: 'checkbox' })),
  };
}

const NAME_FIELD = { name: 'name', label: 'Name', required: true } as const;

const MERAKI_KEY_HELP = (
  <details className="text-muted" style={{ fontSize: '0.85em', marginBottom: '0.75rem' }}>
    <summary style={{ cursor: 'pointer' }}>Where to find the API key and organization ID</summary>
    <strong style={{ display: 'block', marginTop: '0.5rem' }}>Dashboard API key</strong>
    <ol style={{ margin: '0.25rem 0 0', paddingLeft: '1.25rem' }}>
      <li>In the Meraki Dashboard, click your name (top right) &gt; My profile.</li>
      <li>
        Under &quot;API access&quot;, click &quot;Generate new API key&quot;. Copy it at once: the Dashboard shows it
        only once.
      </li>
      <li>API access must be enabled for the organization: Organization &gt; Settings &gt; Dashboard API access.</li>
    </ol>
    <strong style={{ display: 'block', marginTop: '0.5rem' }}>Organization ID</strong>
    <ol style={{ margin: '0.25rem 0 0', paddingLeft: '1.25rem' }}>
      <li>The footer of every Dashboard page shows the organization ID.</li>
      <li>Or open Organization &gt; Settings; the ID is shown next to the organization name.</li>
      <li>
        Or leave this field empty: if the key sees exactly one organization, Plexus detects it. If it sees several,
        save, then click Test Key on the source: it lists each organization with its ID, so you can edit the entry and
        paste the right one.
      </li>
    </ol>
  </details>
);

const MERAKI: SourceFormConfig = {
  noun: 'Meraki Organization',
  addLabel: 'Add Organization',
  idPrefix: 'meraki',
  ...merakiForm,
  blocks: [
    { kind: 'fields', fields: [{ ...NAME_FIELD, placeholder: 'Acme Corp' }] },
    {
      kind: 'fields',
      fields: [
        {
          name: 'secret',
          label: 'Dashboard API key',
          type: 'password',
          required: 'create',
          help: 'A read-only organization admin key is sufficient. Plexus only issues GET requests and stores the key encrypted; it is never shown again.',
        },
      ],
    },
    {
      kind: 'fields',
      columns: 2,
      fields: [
        { name: 'org_id', label: 'Organization ID', placeholder: 'Auto-detect if the key sees one organization' },
        { name: 'base_url', label: 'API base URL', type: 'url', placeholder: DEFAULT_BASE_URL },
      ],
    },
    { kind: 'node', content: MERAKI_KEY_HELP },
    { kind: 'heading', text: 'Scope' },
    {
      kind: 'fields',
      columns: 2,
      fields: [
        { name: 'network_tags', label: 'Only networks tagged', placeholder: 'All networks (comma-separated tags to limit)' },
        { name: 'network_name_contains', label: 'Only networks named like', placeholder: 'All networks' },
      ],
    },
    { kind: 'heading', text: 'Data to collect' },
    toggleFields(OPTION_TOGGLES),
    {
      kind: 'fields',
      maxWidth: 260,
      fields: [{ name: 'requests_per_second', label: 'API requests per second (1-10)', type: 'number', min: 1, max: 10 }],
    },
  ],
};

const CATO: SourceFormConfig = {
  noun: 'Cato Account',
  addLabel: 'Add Account',
  idPrefix: 'cato',
  ...catoForm,
  blocks: [
    { kind: 'fields', fields: [{ ...NAME_FIELD, placeholder: 'Acme Corp Cato' }] },
    {
      kind: 'fields',
      columns: 2,
      fields: [
        {
          name: 'org_id',
          label: 'Account ID',
          required: true,
          placeholder: 'The number in the Cato Management Application URL',
        },
        { name: 'secret', label: 'API key', type: 'password', required: 'create' },
      ],
    },
    {
      kind: 'note',
      content:
        'A key with View permission is sufficient. Plexus only sends read queries and stores the key encrypted; it is never shown again.',
    },
    {
      kind: 'fields',
      fields: [
        {
          name: 'base_url',
          label: 'API URL',
          type: 'url',
          placeholder: CATO_BASE_URL,
          help: 'Change this only if your account is on a regional Cato API host (for example api.us1.catonetworks.com).',
        },
      ],
    },
    { kind: 'heading', text: 'Scope' },
    { kind: 'fields', fields: [{ name: 'site_name_contains', label: 'Only sites named like', placeholder: 'All sites' }] },
    { kind: 'heading', text: 'Data to collect' },
    toggleFields(CATO_OPTION_TOGGLES),
  ],
};

const FMC: SourceFormConfig = {
  noun: 'Cisco FMC',
  addLabel: 'Add FMC',
  idPrefix: 'fmc',
  ...fmcForm,
  blocks: [
    {
      kind: 'note',
      content:
        'The Firewall Management Center that manages your FTDs. Plexus reads devices, interfaces, routing, NAT, access control, site-to-site and remote access VPN over the FMC REST API (read-only).',
    },
    { kind: 'fields', fields: [{ ...NAME_FIELD, placeholder: 'Production FMC' }] },
    {
      kind: 'fields',
      columns: 2,
      fields: [
        {
          name: 'base_url',
          label: 'FMC address',
          type: 'url',
          required: true,
          placeholder: FMC_URL_PLACEHOLDER,
          help: 'https only, host (and port) without a path.',
        },
        {
          name: 'org_id',
          label: 'Domain',
          placeholder: 'Global',
          help: 'A domain name (Global/Branch) or UUID. Blank reads the Global domain.',
        },
      ],
    },
    {
      kind: 'fields',
      columns: 2,
      fields: [
        { name: 'username', label: 'API username', required: true, placeholder: 'plexus-readonly', autoComplete: 'off' },
        { name: 'secret', label: 'Password', type: 'password', required: 'create' },
      ],
    },
    {
      kind: 'note',
      content:
        'Use a dedicated FMC user whose role allows REST API access. Plexus only sends GET requests, never deploys or edits anything, and stores the password encrypted; it is never shown again. An FMC allows about 120 API requests per minute per user, so give this user to Plexus alone.',
    },
    { kind: 'heading', text: 'Scope' },
    {
      kind: 'fields',
      fields: [{ name: 'device_name_contains', label: 'Only devices named like', placeholder: 'All devices' }],
    },
    { kind: 'heading', text: 'Data to collect' },
    toggleFields(FMC_OPTION_TOGGLES),
  ],
};

const PANORAMA: SourceFormConfig = {
  noun: 'Palo Alto Panorama',
  addLabel: 'Add Panorama',
  idPrefix: 'panorama',
  ...panoramaForm,
  blocks: [
    {
      kind: 'note',
      content:
        'The Panorama that manages your Palo Alto Networks firewalls. Plexus reads device groups, templates, interfaces, routing, security and NAT rules, site-to-site VPN and GlobalProtect over the Panorama API (read-only).',
    },
    { kind: 'fields', fields: [{ ...NAME_FIELD, placeholder: 'Production Panorama' }] },
    {
      kind: 'fields',
      columns: 2,
      fields: [
        {
          name: 'base_url',
          label: 'Panorama address',
          type: 'url',
          required: true,
          placeholder: PANORAMA_URL_PLACEHOLDER,
          help: 'https only, host (and port) without a path.',
        },
        {
          name: 'org_id',
          label: 'Device group',
          placeholder: 'All device groups',
          help: 'Blank reads every device group; a name limits the collection to that device group and its children.',
        },
      ],
    },
    {
      kind: 'fields',
      columns: 2,
      fields: [
        {
          name: 'username',
          label: 'Username',
          placeholder: 'plexus-readonly',
          autoComplete: 'off',
          help: 'Leave blank to sign in with an API key',
        },
        { name: 'secret', label: 'Password / API key', type: 'password', required: 'create' },
      ],
    },
    {
      kind: 'note',
      content:
        'Use a dedicated Panorama administrator with a read-only role that allows XML API access. With a username, enter its password; without one, enter a PAN-OS API key. Plexus only reads, never commits or edits anything, and stores the secret encrypted; it is never shown again.',
    },
    { kind: 'heading', text: 'Scope' },
    {
      kind: 'fields',
      fields: [{ name: 'device_name_contains', label: 'Only devices whose name contains', placeholder: 'All devices' }],
    },
    { kind: 'heading', text: 'Data to collect' },
    toggleFields(PANORAMA_OPTION_TOGGLES),
  ],
};

const APPGATE: SourceFormConfig = {
  noun: 'Appgate SDP',
  addLabel: 'Add Appgate',
  idPrefix: 'appgate',
  ...appgateForm,
  blocks: [
    {
      kind: 'note',
      content:
        'An Appgate SDP collective. Plexus reads Controllers, Gateways and the other appliances, sites, policies, entitlements, IP pools and the users connected right now over the Controller admin API (read-only).',
    },
    { kind: 'fields', fields: [{ ...NAME_FIELD, placeholder: 'Acme Appgate SDP' }] },
    {
      kind: 'fields',
      columns: 2,
      fields: [
        {
          name: 'base_url',
          label: 'Controller address',
          type: 'url',
          required: true,
          placeholder: APPGATE_URL_PLACEHOLDER,
          help: (
            <>
              Admin interface of a Controller; <code>/admin</code> is added by Plexus
            </>
          ),
        },
        {
          name: 'org_id',
          label: 'Identity provider',
          placeholder: 'local',
          help: 'The identity provider the admin user signs in with',
        },
      ],
    },
    {
      kind: 'fields',
      columns: 2,
      fields: [
        { name: 'username', label: 'Username', required: true, placeholder: 'plexus-readonly', autoComplete: 'off' },
        {
          name: 'secret',
          label: 'Password',
          type: 'password',
          required: 'create',
          help: 'MFA must be disabled for this API user',
        },
      ],
    },
    {
      kind: 'fields',
      fields: [
        {
          name: 'verify_tls',
          label: 'Verify the Controller certificate',
          type: 'checkbox',
          help: 'Turn off only for a Controller with a self-signed certificate.',
        },
      ],
    },
    {
      kind: 'note',
      content:
        'Use a dedicated admin user with a read-only admin role. Plexus only reads, never changes anything, and stores the password encrypted; it is never shown again.',
    },
    { kind: 'heading', text: 'Scope' },
    { kind: 'fields', fields: [{ name: 'site_name_contains', label: 'Only sites named like', placeholder: 'All sites' }] },
    { kind: 'heading', text: 'Data to collect' },
    toggleFields(APPGATE_OPTION_TOGGLES),
  ],
};

/** Scheduled collection, the same for every provider. */
const SCHEDULE_BLOCKS: SourceFormBlock[] = [
  { kind: 'heading', text: 'Scheduled collection' },
  {
    kind: 'fields',
    fields: [
      {
        name: 'auto_collect',
        label: 'Auto-collect',
        type: 'checkbox',
        help: 'Collect this source on a schedule, so its map and availability stay current. Off: only Collect Now collects it.',
      },
    ],
  },
  {
    kind: 'fields',
    maxWidth: 320,
    fields: [
      {
        name: 'collect_interval_minutes',
        label: 'Interval (minutes)',
        type: 'number',
        min: 0,
        max: 1440,
        help: '0 uses the default interval set in the Sources dialog. Otherwise 5 to 1440 minutes.',
      },
    ],
  },
];

function withSchedule(config: SourceFormConfig): SourceFormConfig {
  return { ...config, blocks: [...config.blocks, ...SCHEDULE_BLOCKS] };
}

export const SOURCE_FORM_CONFIGS: Record<CloudProvider, SourceFormConfig> = {
  meraki: withSchedule(MERAKI),
  cato: withSchedule(CATO),
  fmc: withSchedule(FMC),
  panorama: withSchedule(PANORAMA),
  appgate: withSchedule(APPGATE),
};

/** Every field of a form, for the required-field check. */
export function sourceFormFields(config: SourceFormConfig): SourceField[] {
  return config.blocks.flatMap((b) => (b.kind === 'fields' ? b.fields : []));
}
