// Sub-tabs of Monitoring -> Configure, kept apart from ConfigureTab.tsx so the
// gating can be unit tested (component files may only export components).

export type ConfigureSubTab =
  | 'rules'
  | 'suppressions'
  | 'sla-targets'
  | 'oid-profiles'
  | 'graph-templates'
  | 'host-templates'
  | 'graph-trees';

// Everything that configures what Monitoring collects and alerts on. The
// first four are served by monitoring-gated endpoints; the graph template
// trio (formerly the standalone Graphs page at /graph-templates) by the
// graph-templates router.
export const CONFIGURE_TABS: { key: ConfigureSubTab; label: string; feature: string }[] = [
  { key: 'rules', label: 'Alert Rules', feature: 'monitoring' },
  { key: 'suppressions', label: 'Suppressions', feature: 'monitoring' },
  { key: 'sla-targets', label: 'SLA Targets', feature: 'monitoring' },
  { key: 'oid-profiles', label: 'OID Profiles', feature: 'monitoring' },
  { key: 'graph-templates', label: 'Graph Templates', feature: 'graph-templates' },
  { key: 'host-templates', label: 'Host Templates', feature: 'graph-templates' },
  { key: 'graph-trees', label: 'Graph Trees', feature: 'graph-templates' },
];

/**
 * The Configure tab's gate: every feature one of its sub-tabs needs, so the
 * tab shows when any sub-tab would (and hides only when all are hidden).
 */
export const CONFIGURE_FEATURES: string[] = [...new Set(CONFIGURE_TABS.map((t) => t.feature))];
