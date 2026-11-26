/**
 * The filter rule views of an OPNsense firewall (an inventory host whose
 * config.xml the OPNsense collection stores as its config backup).
 *
 * GET /api/opnsense/hosts/{host_id}/rules             rules of the newest backup
 * GET /api/opnsense/hosts/{host_id}/rules/diff?...    changes between two backups
 */
import { useQuery } from '@tanstack/react-query';

import { apiRequest } from './client';

export type OpnsenseRuleFlag = 'any_any' | 'shadowed' | 'disabled' | 'missing_alias' | 'unused' | 'unused_90d';

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

/**
 * A rule's counter history, kept across collections and counter resets
 * (reboots, filter reloads). Spans end at the last read.
 */
export interface OpnsenseRuleHistory {
  /** UTC 'YYYY-MM-DD HH:MM:SS' of the first collection that read the rule's counters. */
  first_seen_at: string;
  last_seen_at: string | null;
  /** The collection at which the packet counter last grew; null when never. */
  last_hit_at: string | null;
  /** Days from the first read to the last. */
  tracked_days: number;
  /** Days from the last hit (else the first read) to the last read. */
  idle_days: number;
  /** Packets and bytes counted since the first read, across resets. */
  total_packets: number;
  total_bytes: number;
}

/** One distinct flow the firewall log showed for a rule (newest first). */
export interface OpnsenseLogFlow {
  action: string;
  source: string;
  destination: string;
  protocol: string;
  destination_port: number | null;
  hits: number;
  /** UTC 'YYYY-MM-DD HH:MM:SS'. */
  last_seen: string;
}

/** Pass / block evidence of a rule from its firewall log lines (filterlog). */
export interface OpnsenseLogEvidence {
  rule_key: string;
  /** In the view's window (log_evidence.window_hours). */
  passes: number;
  blocks: number;
  /** In the last log_evidence.recent_hours. */
  passes_recent: number;
  blocks_recent: number;
  last_seen: string;
  /** 'igb1 in' - the interfaces and directions it was logged on. */
  seen_on: string[];
  flows: OpnsenseLogFlow[];
}

/** Evidence under a label no rule of the backup has (default deny, bogons...). */
export interface OpnsenseUnmatchedLogEvidence extends OpnsenseLogEvidence {
  name: string;
}

export interface OpnsenseLogEvidenceInfo {
  /** The filterlog_evidence switch of the event receiver settings. */
  enabled: boolean;
  /** When the newest evidence of this firewall was received; null when never. */
  received_at: string | null;
  window_hours: number;
  recent_hours: number;
  bucket_seconds: number;
  unmatched: OpnsenseUnmatchedLogEvidence[];
}

export interface OpnsenseRule {
  number: number;
  key: string;
  uuid: string;
  /** The pf label the firewall's log lines and counters name the rule by. */
  label?: string;
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
  /** Absent on an older server; null when no collection stored the rule's counters. */
  history?: OpnsenseRuleHistory | null;
  /** Absent on an older server; null when the log showed nothing of the rule. */
  log_evidence?: OpnsenseLogEvidence | null;
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

/** The size of an alias's pf table the collection read for path tracing. */
export interface OpnsenseAliasTable {
  entry_count: number;
  /** How many entries the table held when read. */
  total: number;
  /** Cut at the collection's limit: only entry_count of total were read. */
  truncated: boolean;
}

export interface OpnsenseAliasTables {
  /** UTC 'YYYY-MM-DD HH:MM:SS' of the last collection that read them; null when none. */
  read_at: string | null;
  tables: Record<string, OpnsenseAliasTable>;
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
  /** Whether the counter history was read (absent on an older server). */
  history_available?: boolean;
  /** The days without a hit after which an enabled rule is flagged unused_90d. */
  unused_days?: number;
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
  /** Absent when the view is not available. */
  log_evidence?: OpnsenseLogEvidenceInfo;
  /** The alias tables the path trace resolves aliases from (absent on an older server). */
  alias_tables?: OpnsenseAliasTables;
}

/** A rule a path trace hop names, with its firewall log evidence. */
export interface PathLogRuleEvidence {
  number: number;
  description: string;
  rule_key: string;
  /** Whether the rule has "Log packets" on (only logged rules produce evidence). */
  logs_packets: boolean;
  passes: number;
  blocks: number;
  last_seen: string;
}

/** Firewall log evidence on a path trace hop through an OPNsense firewall (server-side only). */
export interface PathLogEvidence {
  window_hours: number;
  /** What the trace decided at this hop: 'allowed', 'blocked' or ''. */
  trace_says: string;
  rules: PathLogRuleEvidence[];
  /** Null when the trace ends are not addresses or networks. */
  flow: {
    matched: boolean;
    passes: number;
    blocks: number;
    last_seen: string;
    rules: string[];
  } | null;
  /** '' when the log agrees with the trace. */
  contradiction: string;
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

/** A rule a configuration change made any-to-any or shadowed (what a rule change alert is raised on). */
export interface OpnsenseRuleFinding {
  kind: 'any_any' | 'shadowed';
  key: string;
  number: number;
  interfaces: string[];
  action: string;
  protocol: string;
  source: string;
  source_port: string;
  destination: string;
  destination_port: string;
  description: string;
  shadowed_by: number | null;
  shadow: '' | 'redundant' | 'conflicting';
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
  /**
   * The rules the change made any-to-any or shadowed (`new`, numbered as in
   * the newer backup) and the ones it no longer flags (`gone`, numbered as in
   * the older one). Absent on an older server.
   */
  findings?: { new: OpnsenseRuleFinding[]; gone: OpnsenseRuleFinding[] };
}

export function useOpnsenseRules(hostId: number | null, enabled = true) {
  return useQuery<OpnsenseRulesView>({
    queryKey: ['opnsense-rules', hostId],
    queryFn: ({ signal }) => apiRequest(`/opnsense/hosts/${hostId}/rules`, { signal }),
    enabled: enabled && hostId != null,
  });
}

export function useOpnsenseRulesDiff(hostId: number | null, fromBackup: number | null, toBackup: number | null) {
  return useQuery<OpnsenseRulesDiff>({
    queryKey: ['opnsense-rules-diff', hostId, fromBackup, toBackup],
    queryFn: ({ signal }) =>
      apiRequest(`/opnsense/hosts/${hostId}/rules/diff?from_backup=${fromBackup}&to_backup=${toBackup}`, { signal }),
    enabled: hostId != null && fromBackup != null && toBackup != null && fromBackup !== toBackup,
  });
}
