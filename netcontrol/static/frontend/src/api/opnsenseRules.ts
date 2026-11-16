/**
 * The filter rule views of an OPNsense firewall (an inventory host whose
 * config.xml the OPNsense collection stores as its config backup).
 *
 * GET /api/opnsense/hosts/{host_id}/rules             rules of the newest backup
 * GET /api/opnsense/hosts/{host_id}/rules/diff?...    changes between two backups
 */
import { useQuery } from '@tanstack/react-query';

import { apiRequest } from './client';

export type OpnsenseRuleFlag = 'any_any' | 'shadowed' | 'disabled' | 'missing_alias' | 'unused';

export interface OpnsenseRuleEndpoint {
  text: string;
  port: string;
  any: boolean;
  negate: boolean;
  cidrs: string[];
  ports: string;
  aliases: string[];
  missing_aliases: string[];
  unresolved: string[];
}

export interface OpnsenseRuleCounters {
  evaluations?: number;
  packets?: number;
  bytes?: number;
  states?: number;
  pf_rules?: number;
}

export interface OpnsenseRule {
  number: number;
  key: string;
  uuid: string;
  tier: string;
  action: string;
  interfaces: string[];
  /** Interface keys the rule applies to (groups expanded); ['*'] for every interface. */
  zones: string[];
  direction: string;
  family: string;
  protocol: string;
  quick: boolean;
  disabled: boolean;
  description: string;
  gateway: string;
  log: boolean;
  source: OpnsenseRuleEndpoint;
  destination: OpnsenseRuleEndpoint;
  unresolved: string[];
}

export interface OpnsenseAnalyzedRule extends OpnsenseRule {
  flags: OpnsenseRuleFlag[];
  shadowed_by: number | null;
  shadow: '' | 'redundant' | 'conflicting';
  missing_aliases: string[];
  stats: OpnsenseRuleCounters | null;
}

export interface OpnsenseInterfaceInfo {
  key: string;
  device: string;
  description: string;
  enabled: boolean;
  addresses: string[];
  dynamic: string[];
}

export interface OpnsenseAlias {
  name: string;
  type: string;
  content: string[];
  description: string;
  enabled: boolean;
}

export interface OpnsenseBackupRef {
  id: number;
  captured_at?: string | null;
  capture_method?: string | null;
}

export interface OpnsenseRulesView {
  host_id: number;
  host: string;
  /** False when the host has no backup or it is no config.xml (`message` says which). */
  available: boolean;
  message: string;
  backup: OpnsenseBackupRef | null;
  stats_collected_at: string | null;
  stats_available: boolean;
  hostname: string;
  interfaces: OpnsenseInterfaceInfo[];
  groups: Record<string, string[]>;
  tiers: string[];
  rules: OpnsenseAnalyzedRule[];
  aliases: OpnsenseAlias[];
  nat: {
    outbound_mode: string;
    port_forwards: Record<string, unknown>[];
    outbound: Record<string, unknown>[];
    one_to_one: Record<string, unknown>[];
  };
  notes: string[];
  summary: Record<OpnsenseRuleFlag | 'rules', number>;
}

export interface OpnsenseFieldChange {
  field: string;
  before: unknown;
  after: unknown;
}

export interface OpnsenseRuleChange {
  key: string;
  number_before: number;
  number_after: number;
  moved: boolean;
  changes: OpnsenseFieldChange[];
  before: OpnsenseRule;
  after: OpnsenseRule;
}

export interface OpnsenseItemDiff {
  added: { key: string; after: Record<string, unknown> }[];
  removed: { key: string; before: Record<string, unknown> }[];
  changed: { key: string; changes: OpnsenseFieldChange[] }[];
}

export interface OpnsenseRulesDiff {
  host_id: number;
  available: boolean;
  message: string;
  from_backup: OpnsenseBackupRef;
  to_backup: OpnsenseBackupRef;
  rules: { added: OpnsenseRule[]; removed: OpnsenseRule[]; changed: OpnsenseRuleChange[] };
  aliases: {
    added: OpnsenseAlias[];
    removed: OpnsenseAlias[];
    changed: { name: string; changes: OpnsenseFieldChange[] }[];
  };
  nat: {
    outbound_mode: { before: string; after: string } | null;
    port_forwards: OpnsenseItemDiff;
    outbound: OpnsenseItemDiff;
    one_to_one: OpnsenseItemDiff;
  };
  summary: { rules: number; aliases: number; nat: number };
}

export function useOpnsenseRules(hostId: number | null, enabled = true) {
  return useQuery<OpnsenseRulesView>({
    queryKey: ['opnsense-rules', hostId],
    queryFn: () => apiRequest(`/opnsense/hosts/${hostId}/rules`),
    enabled: enabled && hostId != null,
  });
}

export function useOpnsenseRulesDiff(hostId: number | null, fromBackup: number | null, toBackup: number | null) {
  return useQuery<OpnsenseRulesDiff>({
    queryKey: ['opnsense-rules-diff', hostId, fromBackup, toBackup],
    queryFn: () =>
      apiRequest(`/opnsense/hosts/${hostId}/rules/diff?from_backup=${fromBackup}&to_backup=${toBackup}`),
    enabled: hostId != null && fromBackup != null && toBackup != null && fromBackup !== toBackup,
  });
}
