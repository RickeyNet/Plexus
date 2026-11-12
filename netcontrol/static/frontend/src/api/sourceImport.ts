import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiRequest } from "./client";
import type { CloudProvider } from "./meraki";

/** What Plexus does with a device once it is an inventory host, beyond pinging it. */
export interface DeviceCapabilities {
  /** Polled over SNMP once its group has an SNMP profile (every host is pinged). */
  snmp_polling: boolean;
  /** Config Backups can read its running configuration. */
  config_backup: boolean;
}

/** The inventory host a device of a source already is. */
export interface ExistingHost {
  host_id: number;
  hostname: string;
  ip_address: string;
  group_id: number | null;
  group_name: string;
}

/** One device of a source's latest collection that can be added to the inventory. */
export interface ImportableDevice {
  /** The device's node id in the snapshot: what an import names it by. */
  key: string;
  name: string;
  /** Management address (one device per address). */
  ip: string;
  model: string;
  serial: string;
  kind: string;
  site: string;
  /** Software platform key (`ftd`, `pan-os`, `meraki-ms`...), '' when unknown. */
  platform: string;
  /** The inventory device type it gets (`icmp_only` when Plexus has no driver for it). */
  device_type: string;
  capabilities: DeviceCapabilities;
  existing: ExistingHost | null;
}

/** GET `/api/sources/{org_ref}/importable-devices`. */
export interface ImportableDevices {
  org_ref: number;
  org_name: string;
  provider: CloudProvider;
  snapshot_id: number | null;
  collected_at: string | null;
  devices: ImportableDevice[];
  /** Why `devices` is empty ('' when it is not). */
  reason: string;
  /** What the provider's devices are and what Plexus can do with them. */
  provider_note: string;
  /** The new group's default name: the source's. */
  suggested_group_name: string;
  /** The most devices one import takes. */
  max_devices: number;
  /** The monitoring poller is on (Settings › Monitoring). */
  monitoring_enabled: boolean;
}

/** Body of POST `/api/sources/{org_ref}/import-devices`: `group_id` or `new_group_name`, not both. */
export interface ImportDevicesRequest {
  device_keys: string[];
  group_id?: number;
  new_group_name?: string;
  /** An existing SNMP profile to assign to the group. */
  snmp_profile_id?: string;
  /** A stored credential to create the group's daily backup policy with. */
  backup_credential_id?: number;
}

/** A device the import did not add. */
export interface ImportSkipped {
  hostname: string;
  ip_address: string;
  reason: string;
  host_id?: number;
  group_id?: number | null;
}

export interface ImportDevicesResult {
  ok: boolean;
  group: { id: number; name: string; created: boolean };
  added: { id: number; hostname: string; ip_address: string }[];
  skipped: ImportSkipped[];
  errors: { hostname: string; ip_address: string; error: string }[];
  counts: { added: number; skipped: number; errors: number };
  /** `kept`: the group already had another profile, which stays. */
  snmp_profile: {
    status: "assigned" | "kept" | "none";
    profile_id: string;
    profile_name: string;
  };
  /** `exists`: the group already had a backup policy, which now covers the new hosts too. */
  backup_policy: {
    status: "created" | "exists" | "none";
    policy_id: number | null;
    name: string;
    /** The policy's schedule and retention (absent when status is `none`). */
    interval_seconds?: number;
    retention_days?: number;
  };
  monitoring_enabled: boolean;
}

/** The devices of a source's latest collection that can be imported (administrators only). */
export function useImportableDevices(orgRef: number | null) {
  return useQuery({
    queryKey: ["meraki", "importable-devices", orgRef],
    queryFn: () =>
      apiRequest<ImportableDevices>(`/sources/${orgRef}/importable-devices`),
    enabled: orgRef != null,
  });
}

export function useImportSourceDevices() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ orgRef, body }: { orgRef: number; body: ImportDevicesRequest }) =>
      apiRequest<ImportDevicesResult>(`/sources/${orgRef}/import-devices`, {
        method: "POST",
        body,
      }),
    // New hosts and groups, an SNMP assignment, maybe a backup policy; the
    // map shows the devices as inventory hosts.
    onSuccess: () => {
      for (const key of [
        "inventory",
        "inventory-groups",
        "inventory-groups-full",
        "snmp-profile-assignments",
        "config-backup-policies",
        "config-backup-summary",
        "topology",
        "meraki",
        "dashboard",
      ]) {
        qc.invalidateQueries({ queryKey: [key] });
      }
    },
  });
}
