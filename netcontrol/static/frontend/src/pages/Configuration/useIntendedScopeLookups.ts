import { useMemo } from 'react';

import { useInventoryGroups } from '@/api/compliance';
import { useDeviceRoles } from '@/api/deviceModel';
import { useGeoSites } from '@/api/floorPlan';

import { hostsFromGroups, type ScopeNames } from './intendedHelpers';

/**
 * The roles, sites, groups and hosts a template or context scope names, from
 * the same queries the host dialog and inventory use (shared cache).
 */
export function useIntendedScopeLookups() {
  const rolesQ = useDeviceRoles();
  const sitesQ = useGeoSites();
  const groupsQ = useInventoryGroups(true);
  const hosts = useMemo(() => (groupsQ.data ? hostsFromGroups(groupsQ.data) : undefined), [groupsQ.data]);
  const names: ScopeNames = { roles: rolesQ.data, sites: sitesQ.data, groups: groupsQ.data, hosts };
  const failed = [
    { what: 'device roles', query: rolesQ },
    { what: 'sites', query: sitesQ },
    { what: 'inventory groups', query: groupsQ },
  ].filter((f) => f.query.isError && !f.query.data);
  return { names, hosts: hosts ?? [], failed };
}
