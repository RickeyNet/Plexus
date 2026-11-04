/**
 * Choosing the credential an SSH read signs in with: the Plexus service
 * credential Settings names by default, or a credential the user picks.
 * Shared by the Topology inventory collection and Inventory discovery.
 */

/** Select value of the Plexus service credential Settings names, sent as `credential_id: null`. */
export const SETTINGS_SERVICE_CREDENTIAL = "service";

/**
 * The credential a read starts with: the service credential Settings names
 * (its id for an administrator, who sees the service list; the Settings
 * placeholder otherwise), else the first service credential, else the first
 * of the user's own. '' when there is none.
 */
export function defaultCollectCredential(
  settingsId: number | null | undefined,
  serviceIds: number[],
  ownIds: number[],
  isAdmin: boolean,
): string {
  if (settingsId != null)
    return isAdmin ? String(settingsId) : SETTINGS_SERVICE_CREDENTIAL;
  if (isAdmin && serviceIds.length) return String(serviceIds[0]);
  return ownIds.length ? String(ownIds[0]) : "";
}

/**
 * The `credential_id` a select value sends: null for the Settings service
 * credential (the server resolves it) and for no choice at all.
 */
export function credentialIdFromChoice(choice: string): number | null {
  if (!choice || choice === SETTINGS_SERVICE_CREDENTIAL) return null;
  const id = parseInt(choice, 10);
  return Number.isFinite(id) ? id : null;
}

/** "name (username)", or the name alone. */
export function credentialLabel(c: { name: string; username?: string }): string {
  return c.username ? `${c.name} (${c.username})` : c.name;
}
