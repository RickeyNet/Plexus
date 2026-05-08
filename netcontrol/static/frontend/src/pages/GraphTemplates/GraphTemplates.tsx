import { useState } from 'react';

import { GraphTemplatesTab } from './GraphTemplatesTab';
import { HostTemplatesTab } from './HostTemplatesTab';
import { GraphTreesTab } from './GraphTreesTab';

type Tab = 'graph-templates' | 'host-templates' | 'graph-trees';

const TABS: { value: Tab; label: string }[] = [
  { value: 'graph-templates', label: 'Graph Templates' },
  { value: 'host-templates', label: 'Host Templates' },
  { value: 'graph-trees', label: 'Graph Trees' },
];

export function GraphTemplates() {
  const [tab, setTab] = useState<Tab>('graph-templates');

  return (
    <div>
      <div className="page-header" style={{ marginBottom: '0.75rem' }}>
        <h2 style={{ margin: 0 }}>Graph Templates</h2>
      </div>

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

      <div className="card" style={{ padding: '1rem' }}>
        {tab === 'graph-templates' && <GraphTemplatesTab />}
        {tab === 'host-templates' && <HostTemplatesTab />}
        {tab === 'graph-trees' && <GraphTreesTab />}
      </div>
    </div>
  );
}
