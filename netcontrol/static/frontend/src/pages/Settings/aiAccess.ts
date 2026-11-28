import type { McpTokenRecord } from '@/api/settings';

/** Path of the MCP endpoint; the server answers with and without a trailing slash. */
export const MCP_PATH = '/mcp';

/** The sentence shown wherever tokens are managed. Exact copy; do not reword. */
export const DATA_NOTICE =
  'Data returned by these tools is sent to the AI provider your client uses. Secrets in device configurations are masked. Configurations, IP addresses and hostnames are not.';

/** One line per data category, shown beside its checkbox. */
export const CATEGORY_HELP: Record<string, string> = {
  inventory: 'Devices, groups, models and addresses.',
  configs: 'Stored device configurations: search, read, compare, drift. Secrets are masked.',
  compliance: 'Compliance scan results and summaries.',
  monitoring: 'Alerts, device health, SLA status and outages.',
  topology: 'Neighbors, interfaces, topology changes and path trace.',
  software: 'Software versions, advisories and CVEs.',
  traffic: 'Where a MAC or IP address was seen, and top talkers from flow records.',
  audit: 'The Plexus audit log. Needs an owner who is an admin.',
};

export function endpointUrl(baseUrl: string): string {
  return `${baseUrl.replace(/\/+$/, '')}${MCP_PATH}`;
}

export interface ConnectionSnippet {
  label: string;
  /** Where the text goes: a shell, a config file. */
  hint: string;
  text: string;
}

/** Ready-to-paste connection settings for the clients people use most. */
export function connectionSnippets(baseUrl: string, token: string): ConnectionSnippet[] {
  const url = endpointUrl(baseUrl);
  const header = `Authorization: Bearer ${token}`;
  const desktop = {
    mcpServers: {
      plexus: { command: 'npx', args: ['-y', 'mcp-remote', url, '--header', header] },
    },
  };
  return [
    {
      label: 'Claude Code',
      hint: 'Run in a terminal.',
      text: `claude mcp add --transport http plexus ${url} --header "${header}"`,
    },
    {
      label: 'Claude Desktop',
      hint: 'Add to claude_desktop_config.json, then restart Claude Desktop.',
      text: JSON.stringify(desktop, null, 2),
    },
    {
      label: 'Other MCP clients',
      hint: 'Streamable HTTP transport with a bearer token.',
      text: `URL: ${url}\nTransport: Streamable HTTP\nHeader: ${header}`,
    },
  ];
}

export type TokenStatus = 'active' | 'expired' | 'revoked';

/** A token expires at the end of its expiry day (UTC), as on the server. */
export function tokenStatus(record: McpTokenRecord, now: Date = new Date()): TokenStatus {
  if (record.revoked_at) return 'revoked';
  const expires = (record.expires_at || '').trim();
  if (!expires) return 'active';
  const today = now.toISOString().slice(0, expires.length <= 10 ? 10 : 19).replace('T', ' ');
  return today > expires ? 'expired' : 'active';
}

/** The UTC date `days` after `now` as YYYY-MM-DD, the form of a token's expiry date. */
export function utcDateAfter(days: number, now: Date = new Date()): string {
  return new Date(now.getTime() + days * 86_400_000).toISOString().slice(0, 10);
}

export interface TokenForm {
  name: string;
  ownerId: number | null;
  ownerIsAdmin: boolean;
  categories: string[];
  /** YYYY-MM-DD. */
  expiresAt: string;
}

export type TokenFormErrors = Partial<Record<'name' | 'owner' | 'categories' | 'expiresAt', string>>;

export const TOKEN_NAME_MAX = 80;

/**
 * `expiryMaxDays` is the server's limit (`expiry_max_days` of the token list); the server checks
 * the date again against its own clock.
 */
export function validateTokenForm(
  form: TokenForm,
  expiryMaxDays: number,
  now: Date = new Date(),
): TokenFormErrors {
  const errors: TokenFormErrors = {};
  const name = form.name.trim();
  if (!name) errors.name = 'Enter a name for the token.';
  else if (name.length > TOKEN_NAME_MAX) errors.name = `Use ${TOKEN_NAME_MAX} characters or fewer.`;
  if (form.ownerId === null) errors.owner = 'Choose the user this token acts as.';
  if (form.categories.length === 0) errors.categories = 'Choose at least one data category.';
  else if (form.categories.includes('audit') && !form.ownerIsAdmin)
    errors.categories = 'The audit category needs an owner who is an admin.';
  if (!form.expiresAt) errors.expiresAt = 'Enter an expiry date.';
  else if (!/^\d{4}-\d{2}-\d{2}$/.test(form.expiresAt))
    errors.expiresAt = 'Use a date in the form YYYY-MM-DD.';
  else if (form.expiresAt < utcDateAfter(0, now)) errors.expiresAt = 'Choose today or a later date.';
  else if (form.expiresAt > utcDateAfter(expiryMaxDays, now))
    errors.expiresAt = `Choose a date at most ${expiryMaxDays} days from today.`;
  return errors;
}
