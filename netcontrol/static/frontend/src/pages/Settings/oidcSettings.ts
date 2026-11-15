import type { OidcGroupMapping } from '@/api/settings';

export const OIDC_CALLBACK_PATH = '/api/auth/oidc/callback';
export const OIDC_MAX_GROUP_MAPPINGS = 200;
export const OIDC_BUTTON_LABEL_MAX = 60;

/** The redirect URI to register at the provider: the configured one, else
 * this site's origin plus the callback path (what the server derives when
 * the browser reaches it directly or through a proxy that keeps the host). */
export function oidcRedirectUri(configured: string, origin: string): string {
  return configured.trim() || `${origin}${OIDC_CALLBACK_PATH}`;
}

/** Admin groups are edited one per line; empty lines are kept while typing
 * and dropped by the server. */
export function parseGroupLines(text: string): string[] {
  return text.split(/\r?\n/);
}

export function updateMapping(
  mappings: OidcGroupMapping[],
  index: number,
  patch: Partial<OidcGroupMapping>,
): OidcGroupMapping[] {
  return mappings.map((m, i) => (i === index ? { ...m, ...patch } : m));
}

export function removeMapping(mappings: OidcGroupMapping[], index: number): OidcGroupMapping[] {
  return mappings.filter((_, i) => i !== index);
}

/** Why the OIDC block cannot be saved as it is, or null. Mirrors the
 * server's 400s so the admin sees them before submitting. */
export function oidcProblem(o: {
  enabled: boolean;
  issuer: string;
  client_id: string;
  button_label: string;
  group_mappings: OidcGroupMapping[];
}): string | null {
  if (o.enabled) {
    const issuer = o.issuer.trim();
    if (!issuer) return 'Enter the OIDC issuer URL.';
    if (!isAllowedUrl(issuer)) return 'The OIDC issuer must be an https URL.';
    if (!o.client_id.trim()) return 'Enter the OIDC client ID.';
  }
  if (o.button_label.trim().length > OIDC_BUTTON_LABEL_MAX)
    return `The SSO button label is limited to ${OIDC_BUTTON_LABEL_MAX} characters.`;
  if (o.group_mappings.length > OIDC_MAX_GROUP_MAPPINGS)
    return `At most ${OIDC_MAX_GROUP_MAPPINGS} group mappings are allowed.`;
  return null;
}

/** https, or http on a loopback host (a lab provider); as the server checks. */
export function isAllowedUrl(value: string): boolean {
  try {
    const url = new URL(value);
    if (url.protocol === 'https:') return !!url.hostname;
    return url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  } catch {
    return false;
  }
}
