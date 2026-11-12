import { useAuthStatus } from '@/api/auth';
import { useConfigBackupSummary } from '@/api/configuration';
import type { DashboardResponse } from '@/api/dashboard';
import type { TopologySource } from '@/api/meraki';
import { useSnmpProfiles } from '@/api/inventory';
import { useFlowStatus } from '@/api/networkTools';
import { useNotificationChannels } from '@/api/settings';
import { canUseFeature } from '@/lib/tabGating';

import {
  type NotSetUpEntry,
  type PanelKey,
  type PanelVisibility,
  type SetupStep,
  buildSetupSteps,
  notSetUpEntries,
  panelVisibility,
  type SetupInputs,
} from './setupGuide';

export interface SetupGuide {
  /** A step's state is still loading: render no checklist yet. */
  stepsPending: boolean;
  steps: SetupStep[];
  panels: Record<PanelKey, PanelVisibility>;
  notSetUp: NotSetUpEntry[];
}

/**
 * Gathers what the setup guide reads. Each request is made only when the
 * user may make it: SNMP profiles need the inventory feature, notification
 * channels are admin-only, backups and flows have their own features. The
 * Dashboard already holds the dashboard response and the topology sources
 * (requested only with the topology feature) and passes them in.
 */
export function useSetupGuide(
  dashboard: DashboardResponse | undefined,
  /** The topology sources; undefined while loading, on error or without the feature. */
  sources: TopologySource[] | undefined,
  sourcesPending: boolean,
  canTopology: boolean,
): SetupGuide {
  const { data: auth } = useAuthStatus();
  const isAdmin = auth?.role === 'admin';
  const can = {
    topology: canTopology,
    inventory: canUseFeature('inventory', auth),
    configBackups: canUseFeature('config-backups', auth),
    trafficAnalysis: canUseFeature('traffic-analysis', auth),
  };
  // Until auth is known nothing is enabled, and the steps wait for it.
  const authKnown = auth !== undefined;

  // Only the admin step uses the profiles (to pick its link).
  const wantProfiles = authKnown && isAdmin && can.inventory;
  const profiles = useSnmpProfiles(wantProfiles);
  const wantChannels = authKnown && isAdmin;
  const channels = useNotificationChannels(wantChannels, false);
  const wantBackups = authKnown && can.configBackups;
  const backupSummary = useConfigBackupSummary(wantBackups);
  const wantFlows = authKnown && can.trafficAnalysis;
  const flowStatus = useFlowStatus(wantFlows);

  const inputs: SetupInputs = {
    isAdmin,
    can,
    sources: canTopology ? sources : undefined,
    totalHosts: dashboard?.stats?.total_hosts,
    polledDevices: dashboard?.device_health?.length,
    snmpProfiles: profiles.data?.length,
    backupPolicies: backupSummary.data?.total_policies,
    backups: backupSummary.data?.total_backups,
    notificationChannels: channels.data?.channels.length,
    flowCollectorEnabled: flowStatus.data?.enabled,
  };
  // A disabled query stays pending forever, so only an enabled one counts.
  const stepsPending =
    !authKnown ||
    dashboard === undefined ||
    (canTopology && sourcesPending) ||
    (wantProfiles && profiles.isPending) ||
    (wantChannels && channels.isPending) ||
    (wantBackups && backupSummary.isPending);

  const panels = panelVisibility(inputs, {
    flowStatus: wantFlows && flowStatus.isPending,
    backupSummary: wantBackups && backupSummary.isPending,
  });
  // Without auth every feature reads as missing; wait rather than drop them.
  if (!authKnown) {
    panels.talkers = 'pending';
    panels.backups = 'pending';
  }

  return {
    stepsPending,
    steps: stepsPending ? [] : buildSetupSteps(inputs),
    panels,
    notSetUp: notSetUpEntries(panels, inputs),
  };
}
