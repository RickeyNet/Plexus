/**
 * Syslog alert rule hooks. Backend: /api/monitoring/syslog-rules
 * (netcontrol/routes/syslog_rules.py). One merged list of the built-in rules
 * (only enabled and severity change) and the custom rules (full CRUD), and a
 * test endpoint that explains what a sample message would do.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest, queryString } from './client';

export type SyslogMatchType = 'tag' | 'contains' | 'regex';
export type SyslogSeverity = 'info' | 'warning' | 'critical';

export interface SyslogRule {
  /** Null for a built-in rule. */
  id: number | null;
  /** Names the rule in the alert metric (`syslog_<key>`) and dedup key. */
  key: string;
  metric: string;
  name: string;
  description: string;
  builtin: boolean;
  enabled: boolean;
  severity: string;
  /** `builtin` for a built-in rule. */
  match_type: string;
  pattern: string;
  clear_pattern: string;
  /** Built-in rules: the message tags that raise and clear them. */
  tags: string[];
  clear_tags: string[];
  /** Built-in rules: the device families they cover. */
  families: string[];
  threshold_count: number;
  threshold_window_seconds: number;
  auto_resolve_minutes: number;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface SyslogRuleBody {
  name: string;
  enabled?: boolean;
  match_type: SyslogMatchType;
  pattern: string;
  clear_pattern?: string;
  severity: SyslogSeverity;
  threshold_count: number;
  threshold_window_seconds: number;
  auto_resolve_minutes: number;
}

export interface SyslogMatch {
  action: 'raise' | 'clear' | '';
  instance: string;
}

export interface SyslogTestResult {
  /** The tag as written (`LINK-3-UPDOWN`); empty when none was found. */
  tag: string;
  /** The key rules match the tag by (`LINK-UPDOWN`). */
  match_tag: string;
  text: string;
  matches: (SyslogMatch & { key: string; name: string; builtin: boolean; enabled: boolean })[];
  /** The unsaved rule's result, when one was sent. */
  draft: SyslogMatch | null;
  config_change: boolean;
  /** `interface_down`, `reload`, `restart` or empty. */
  repoll: string;
  /** The program (RFC 5424 APP-NAME / RFC 3164 tag); empty when none was found. */
  program?: string;
  /** Why an OPNsense firewall's message starts a re-collection: `gateway`, `carp`, `vpn`, `config` or empty. */
  recollect?: string;
}

const PATH = '/monitoring/syslog-rules';
const KEY = ['syslog-rules'];
const ACTIVITY_KEY = ['syslog-rules-activity'];

export function useSyslogRules() {
  return useQuery<SyslogRule[]>({ queryKey: KEY, queryFn: () => apiRequest(PATH) });
}

export function useCreateSyslogRule() {
  const qc = useQueryClient();
  return useMutation<SyslogRule, Error, SyslogRuleBody>({
    mutationFn: (data) => apiRequest(PATH, { method: 'POST', body: data }),
    onSuccess: () => {
      // A new rule changes what counts as unmatched: scan again, without
      // holding the save open for it.
      void qc.invalidateQueries({ queryKey: ACTIVITY_KEY });
      return qc.invalidateQueries({ queryKey: KEY });
    },
  });
}

export function useUpdateSyslogRule() {
  const qc = useQueryClient();
  return useMutation<SyslogRule, Error, { id: number; data: Partial<SyslogRuleBody> }>({
    mutationFn: ({ id, data }) => apiRequest(`${PATH}/${id}`, { method: 'PUT', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

export function useDeleteSyslogRule() {
  const qc = useQueryClient();
  return useMutation<{ ok: boolean; alerts_resolved: number }, Error, number>({
    mutationFn: (id) => apiRequest(`${PATH}/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

export function usePatchBuiltinSyslogRule() {
  const qc = useQueryClient();
  return useMutation<SyslogRule, Error, { key: string; data: { enabled?: boolean; severity?: string } }>({
    mutationFn: ({ key, data }) => apiRequest(`${PATH}/builtin/${encodeURIComponent(key)}`, { method: 'PATCH', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

export function useTestSyslogMessage() {
  return useMutation<SyslogTestResult, Error, { message: string; rule?: SyslogRuleBody }>({
    mutationFn: (data) => apiRequest(`${PATH}/test`, { method: 'POST', body: data }),
  });
}

/** One rule's matches in the scanned window (rules without a match are absent). */
export interface SyslogRuleActivity {
  /** The rule's `SyslogRule.key`. */
  key: string;
  raised: number;
  cleared: number;
  hosts: number;
  last_at: string;
}

/** Unmatched messages of one tag, or of one program when untagged, or of neither. */
export interface SyslogUnmatchedGroup {
  /** The match key of the tag (`SEC-IPACCESSLOGP`); '' for an untagged group. */
  tag: string;
  /** The tag as the device wrote it (`SEC-6-IPACCESSLOGP`). */
  raw_tag: string;
  /** The program of an untagged group (`sshd`); '' otherwise. */
  program: string;
  count: number;
  hosts: number;
  device_types: string[];
  last_at: string;
  /** One message of the group, at most 300 characters. */
  sample: string;
  /**
   * The built-in rule (`link_flap`, `ospf_neighbor`, `bgp_neighbor`,
   * `power_supply`, `fan`, `auth_failure`) or trigger (`config_change`,
   * `repoll`) the group looks like the subject of; '' for none. A keyword
   * hint, not a match.
   */
  related: string;
  /**
   * `related` handles this very tag, so the text of these messages did not
   * meet its pattern: the opposite event (an interface coming up), or
   * wording the rule does not cover.
   */
  known_tag: boolean;
}

export interface SyslogUnknownSource {
  source_ip: string;
  count: number;
  last_at: string;
}

/** What the syslog messages received in the last `hours` hours did. */
export interface SyslogActivity {
  hours: number;
  /** The most messages one scan reads (the newest ones). */
  limit: number;
  /** `matched + unmatched + unknown_source`. */
  scanned: number;
  /** The window held more than `limit` messages. */
  truncated: boolean;
  /** The oldest scanned message; '' when none was. */
  oldest_at: string;
  matched: number;
  unmatched: number;
  /** Messages from addresses that match no inventory host (rules never see them). */
  unknown_source: number;
  rules: SyslogRuleActivity[];
  triggers: { config_change: number; repoll: number; recollect: number };
  /** The top 100 unmatched groups by count. */
  unmatched_tags: SyslogUnmatchedGroup[];
  /** The top 20 unknown source addresses (empty for a group-limited user). */
  unknown_sources: SyslogUnknownSource[];
  /** Messages of inventory hosts scanned, per transport they arrived over. */
  transports: { udp: number; tcp: number; tls: number };
  /** Inventory hosts that sent at least one message over UDP in the window. */
  udp_hosts: number;
  /** The Act on UDP messages setting: off, UDP messages are stored but not acted on. */
  udp_actions: boolean;
}

/**
 * The on-demand scan of received messages. It is not free, so it never
 * refetches on an interval; the tab has a Refresh button. Its own key, so
 * enabling or editing a rule does not start a new scan (creating one does).
 */
export function useSyslogActivity(hours: number) {
  return useQuery<SyslogActivity>({
    queryKey: [...ACTIVITY_KEY, hours],
    queryFn: () => apiRequest(`${PATH}/activity${queryString({ hours })}`),
    staleTime: 60_000,
  });
}
