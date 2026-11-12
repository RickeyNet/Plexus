import type { AuthStatus } from '@/api/auth';

import { canUseFeature } from './tabGating';

/** Which kinds of source this user may add from the app-wide Add source action. */
export interface AddSourceAccess {
  /** Meraki, Cato, FMC, Panorama, Appgate: admin-only, behind the topology feature. */
  org: boolean;
  /** AWS, Azure, GCP accounts: admin-only, added under Cloud Visibility. */
  cloud: boolean;
}

/**
 * What the Add source action offers this user. Adding a source of either
 * kind is admin-only on the server; a feature an admin hid globally takes
 * its sources out of the list.
 */
export function addSourceAccess(auth: AuthStatus | undefined): AddSourceAccess {
  const isAdmin = auth?.authenticated === true && auth.role === 'admin';
  return {
    org: isAdmin && canUseFeature('topology', auth),
    cloud: isAdmin && canUseFeature('cloud-visibility', auth),
  };
}

/** Whether the Add source action is shown at all. */
export function canAddSource(access: AddSourceAccess): boolean {
  return access.org || access.cloud;
}
