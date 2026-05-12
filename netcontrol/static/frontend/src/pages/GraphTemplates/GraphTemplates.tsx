import { useState } from 'react';

import { PageHelp } from '@/components/PageHelp';
import { GraphTemplatesTab } from './GraphTemplatesTab';
import { HostTemplatesTab } from './HostTemplatesTab';
import { GraphTreesTab } from './GraphTreesTab';

type Tab = 'graph-templates' | 'host-templates' | 'graph-trees';

const TABS: { value: Tab; label: string }[] = [
  { value: 'graph-templates', label: 'Graph Templates' },
  { value: 'host-templates', label: 'Host Templates' },
  { value: 'graph-trees', label: 'Graph Trees' },
];

const TAB_HELP: Record<Tab, { title: string; text: string }> = {
  'graph-templates': {
    title: 'Reusable Graph Definitions',
    text: 'A graph template is a chart recipe — what to plot, how to aggregate, what colors and units. Define once, apply to many devices.',
  },
  'host-templates': {
    title: 'Map Device Types to Graphs',
    text: 'A host template binds graph templates to a class of device (e.g., "Catalyst 9300"). When a matching device is added to inventory, its graphs auto-appear.',
  },
  'graph-trees': {
    title: 'Hierarchical Graph Navigation',
    text: 'Organize graphs into trees by site, role, or customer. Trees show up in dashboards and the device detail page for fast drill-down.',
  },
};

export function GraphTemplates() {
  const [tab, setTab] = useState<Tab>('graph-templates');

  return (
    <div>
      <div className="page-header" style={{ marginBottom: '0.75rem' }}>
        <h2 style={{ margin: 0 }}>Graph Templates</h2>
      </div>

      <PageHelp
        pageKey="graph-templates"
        title="Graph Templates & Auto-Graphing"
        text="Manage reusable graph definitions that auto-apply to devices. Create host templates to map device types to graphs, and organize with graph trees for hierarchical navigation."
      />

      <div className="tab-controls">
        {TABS.map((t) => (
          <button
            key={t.value}
            type="button"
            className={`btn btn-sm btn-secondary upgrade-tab-btn${tab === t.value ? ' active' : ''}`}
            onClick={() => setTab(t.value)}
          >
            {t.label}
          </button>
        ))}
      </div>

      <PageHelp pageKey={`graph-templates.${tab}`} title={TAB_HELP[tab].title} text={TAB_HELP[tab].text} />

      <div className="card" style={{ padding: '1rem' }}>
        {tab === 'graph-templates' && <GraphTemplatesTab />}
        {tab === 'host-templates' && <HostTemplatesTab />}
        {tab === 'graph-trees' && <GraphTreesTab />}
      </div>
    </div>
  );
}
