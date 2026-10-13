import { useAuthStatus } from '@/api/auth';
import { PageHelp } from '@/components/PageHelp';
import { TabBar } from '@/components/TabBar';
import { visibleTabs } from '@/lib/tabGating';
import { usePathTab } from '@/lib/usePathTab';

import { GraphTemplatesTab } from '@/pages/GraphTemplates/GraphTemplatesTab';
import { GraphTreesTab } from '@/pages/GraphTemplates/GraphTreesTab';
import { HostTemplatesTab } from '@/pages/GraphTemplates/HostTemplatesTab';

import { OidProfilesTab } from './OidProfilesTab';
import { RulesTab } from './RulesTab';
import { SlaTargetsTab } from './SlaTargetsTab';
import { SuppressionsTab } from './SuppressionsTab';
import { CONFIGURE_TABS, type ConfigureSubTab } from './configureTabs';

const TAB_KEYS = CONFIGURE_TABS.map((t) => t.key);

// The graph sub-tabs carry their own help; the monitoring ones explain
// themselves inline.
const GRAPH_HELP: Partial<Record<ConfigureSubTab, { title: string; text: string }>> = {
  'graph-templates': {
    title: 'Reusable Graph Definitions',
    text: 'A graph template is a chart recipe - what to plot, how to aggregate, what colors and units. Define once, apply to many devices.',
  },
  'host-templates': {
    title: 'Map Device Types to Graphs',
    text: 'A host template binds graph templates to a class of device (e.g., "Catalyst 9300"). When a matching device is added to inventory, its graphs auto-appear.',
  },
  'graph-trees': {
    title: 'Graph Trees',
    text: 'A graph tree is a named outline you build by hand: header nodes for grouping (by site, role or customer) with device and graph nodes underneath, ordered by sort order. Trees are stored and edited here only - no other page renders them yet.',
  },
};

export function ConfigureTab() {
  const { data: auth } = useAuthStatus();
  const shownTabs = visibleTabs(CONFIGURE_TABS, auth);
  const [tab, selectTab] = usePathTab(
    '/monitoring/configure',
    TAB_KEYS,
    'rules',
    auth ? shownTabs.map((t) => t.key) : undefined,
  );
  const help = GRAPH_HELP[tab];

  return (
    <div>
      <TabBar tabs={shownTabs} active={tab} onChange={selectTab} size="sm" aria-label="Monitoring configuration" />

      {tab === 'rules' && <RulesTab />}
      {tab === 'suppressions' && <SuppressionsTab />}
      {tab === 'sla-targets' && <SlaTargetsTab />}
      {tab === 'oid-profiles' && <OidProfilesTab />}

      {help && (
        <>
          <PageHelp pageKey={`graph-templates.${tab}`} title={help.title} text={help.text} />
          <div className="card" style={{ padding: '1rem' }}>
            {tab === 'graph-templates' && <GraphTemplatesTab />}
            {tab === 'host-templates' && <HostTemplatesTab />}
            {tab === 'graph-trees' && <GraphTreesTab />}
          </div>
        </>
      )}
    </div>
  );
}
