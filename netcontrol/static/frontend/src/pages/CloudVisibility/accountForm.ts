// What the cloud account form asks for, per provider. The form turns the
// answers into the auth_config object the collectors read, so nobody has to
// write that JSON by hand.

export interface AuthField {
  /** auth_config key the value is saved under. */
  key: string;
  label: string;
  placeholder?: string;
  help?: string;
  /** Keys and secrets: masked while typing. */
  secret?: boolean;
  /** Comma or newline separated, saved as a list. */
  list?: boolean;
  /** A pasted JSON document (a key file), saved as an object. */
  json?: boolean;
  optional?: boolean;
}

export interface AuthMethod {
  key: string;
  label: string;
  help: string;
  /** Saved as the account's auth_type. */
  authType: string;
  fields: AuthField[];
}

export interface AuthSection {
  title: string;
  help: string;
  fields: AuthField[];
}

export interface ProviderForm {
  identifierLabel: string;
  identifierPlaceholder: string;
  identifierHelp: string;
  /** auth_config key the identifier is also saved under, where sync reads it from there. */
  identifierKey?: string;
  /** Set for providers that are read region by region. */
  regionHelp?: string;
  /** Set for providers that can list their own regions. */
  allRegionsHelp?: string;
  methods: AuthMethod[];
  /** Optional sync settings; every field may be left empty. */
  sections: AuthSection[];
}

const AWS: ProviderForm = {
  identifierLabel: 'AWS account ID',
  identifierPlaceholder: '123456789012',
  identifierHelp: 'Optional, shown in the accounts table.',
  regionHelp: 'Comma-separated. Left empty, only us-east-1 is read.',
  allRegionsHelp: 'Every region enabled for the account is read. Discovery takes longer.',
  methods: [
    {
      key: 'access_key',
      label: 'Access key',
      help: 'The access key of an IAM user with read-only access.',
      authType: 'api_keys',
      fields: [
        { key: 'access_key_id', label: 'Access key ID', placeholder: 'AKIA...' },
        { key: 'secret_access_key', label: 'Secret access key', secret: true },
      ],
    },
    {
      key: 'assume_role',
      label: 'IAM role',
      help: 'Plexus assumes a role in the account. Best for reading several AWS accounts.',
      authType: 'assume_role',
      fields: [
        { key: 'role_arn', label: 'Role ARN', placeholder: 'arn:aws:iam::123456789012:role/plexus-readonly' },
        { key: 'external_id', label: 'External ID', optional: true, help: 'Only if the role requires one.' },
        {
          key: 'access_key_id',
          label: 'Access key ID',
          optional: true,
          placeholder: 'AKIA...',
          help: 'The key that assumes the role. Leave both key fields empty to use the credentials of the Plexus server.',
        },
        { key: 'secret_access_key', label: 'Secret access key', optional: true, secret: true },
      ],
    },
    {
      key: 'server',
      label: 'Credentials of the Plexus server',
      help: 'Nothing to enter: the instance profile or environment credentials of the server are used.',
      authType: 'workload_identity',
      fields: [],
    },
  ],
  sections: [
    {
      title: 'Flow logs',
      help: 'Needed for Pull Flow only. VPC Flow Logs are read from CloudWatch Logs.',
      fields: [{ key: 'log_group_name', label: 'Flow log group', placeholder: '/aws/vpc/flow-logs' }],
    },
    {
      title: 'Traffic metrics',
      help: 'Needed for Pull Traffic only. CloudWatch metrics are read for the resources listed.',
      fields: [
        { key: 'resource_ids', label: 'Resource IDs', list: true, placeholder: 'i-1234567890abcdef0, i-0fedcba0987654321' },
        { key: 'metric_names', label: 'Metric names', list: true, placeholder: 'Default: NetworkIn, NetworkOut, NetworkPacketsIn, NetworkPacketsOut' },
        { key: 'metric_namespace', label: 'Metric namespace', placeholder: 'Default: AWS/EC2' },
        { key: 'resource_dimension_name', label: 'Resource dimension', placeholder: 'Default: InstanceId' },
      ],
    },
  ],
};

const AZURE: ProviderForm = {
  identifierLabel: 'Subscription ID',
  identifierPlaceholder: '00000000-0000-0000-0000-000000000000',
  identifierHelp: 'The subscription that discovery reads.',
  identifierKey: 'subscription_id',
  methods: [
    {
      key: 'service_principal',
      label: 'Service principal',
      help: 'An app registration with Reader access to the subscription.',
      authType: 'service_principal',
      fields: [
        { key: 'tenant_id', label: 'Tenant ID' },
        { key: 'client_id', label: 'Client (application) ID' },
        { key: 'client_secret', label: 'Client secret', secret: true },
      ],
    },
    {
      key: 'server',
      label: 'Credentials of the Plexus server',
      help: 'Nothing to enter: the managed identity or environment credentials of the server are used.',
      authType: 'workload_identity',
      fields: [],
    },
  ],
  sections: [
    {
      title: 'Flow logs',
      help: 'Needed for Pull Flow only. NSG flow logs are read from a storage account.',
      fields: [
        { key: 'storage_account_name', label: 'Storage account', placeholder: 'mystorageacct' },
        { key: 'container_name', label: 'Container', placeholder: 'insights-logs-networksecuritygroupflowevent' },
        {
          key: 'storage_account_key',
          label: 'Storage account key',
          secret: true,
          help: 'Leave empty to read the storage account with the sign-in above.',
        },
      ],
    },
    {
      title: 'Traffic metrics',
      help: 'Needed for Pull Traffic only. Azure Monitor metrics are read for the resources listed.',
      fields: [
        { key: 'resource_ids', label: 'Resource IDs', list: true, placeholder: '/subscriptions/.../networkInterfaces/nic-1' },
        { key: 'metric_names', label: 'Metric names', list: true, placeholder: 'Default: BytesIn, BytesOut, PacketsIn, PacketsOut' },
      ],
    },
  ],
};

const GCP: ProviderForm = {
  identifierLabel: 'Project ID',
  identifierPlaceholder: 'my-gcp-project',
  identifierHelp: 'The project that discovery, flow logs and traffic metrics read.',
  identifierKey: 'project_id',
  methods: [
    {
      key: 'service_account',
      label: 'Service account key',
      help: 'The JSON key file of a service account with viewer access to the project.',
      authType: 'api_keys',
      fields: [
        { key: 'service_account_json', label: 'Key file contents', json: true, secret: true, placeholder: '{ "type": "service_account", ... }' },
      ],
    },
    {
      key: 'server',
      label: 'Credentials of the Plexus server',
      help: 'Nothing to enter: the Application Default Credentials of the server are used.',
      authType: 'workload_identity',
      fields: [],
    },
  ],
  sections: [
    {
      title: 'Traffic metrics',
      help: 'Needed for Pull Traffic only, and only to read other metrics than the defaults.',
      fields: [
        { key: 'metric_types', label: 'Metric types', list: true, placeholder: 'Default: instance network received and sent bytes' },
      ],
    },
  ],
};

const OTHER: ProviderForm = {
  identifierLabel: 'Account / Subscription / Project',
  identifierPlaceholder: '',
  identifierHelp: '',
  methods: [
    {
      key: 'server',
      label: 'Credentials of the Plexus server',
      help: 'Nothing to enter. Provider settings go under Additional settings.',
      authType: 'manual',
      fields: [],
    },
  ],
  sections: [],
};

/** The region scope that reads every region enabled for the account. */
export const ALL_REGIONS = 'all';

export function isAllRegions(regionScope: string | null | undefined): boolean {
  const scope = (regionScope ?? '').trim().toLowerCase();
  return scope === ALL_REGIONS || scope === '*';
}

export function providerForm(provider: string): ProviderForm {
  const n = provider.toLowerCase();
  if (n === 'aws') return AWS;
  if (n === 'azure') return AZURE;
  if (n === 'gcp') return GCP;
  return OTHER;
}

export function authMethod(form: ProviderForm, key: string): AuthMethod {
  return form.methods.find((m) => m.key === key) ?? form.methods[0];
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * The auth_config for the answers given: the chosen sign-in, the optional sync
 * settings that were filled in, then any additional settings on top.
 */
export function buildAuthConfig(
  form: ProviderForm,
  methodKey: string,
  values: Record<string, string>,
  identifier: string,
  extraText: string,
): { config: Record<string, unknown>; error?: undefined } | { error: string } {
  const config: Record<string, unknown> = {};
  if (form.identifierKey && identifier.trim()) config[form.identifierKey] = identifier.trim();

  const method = authMethod(form, methodKey);
  const optionalFields = form.sections.flatMap((s) => s.fields).map((f) => ({ ...f, optional: true }));
  for (const field of [...method.fields, ...optionalFields]) {
    const text = (values[field.key] ?? '').trim();
    if (!text) {
      if (!field.optional) return { error: `${field.label} is required` };
      continue;
    }
    if (field.list) {
      const items = text.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean);
      if (items.length) config[field.key] = items;
    } else if (field.json) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        return { error: `${field.label} is not valid JSON` };
      }
      if (!isObject(parsed)) return { error: `${field.label} is not valid JSON` };
      config[field.key] = parsed;
    } else {
      config[field.key] = text;
    }
  }

  if (extraText.trim()) {
    let extra: unknown;
    try {
      extra = JSON.parse(extraText);
    } catch {
      return { error: 'Additional settings are not valid JSON' };
    }
    if (!isObject(extra)) return { error: 'Additional settings must be a JSON object' };
    Object.assign(config, extra);
  }
  return { config };
}
