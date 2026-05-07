import { useState } from 'react';

import { BackupsTab } from './BackupsTab';
import { CampaignsTab } from './CampaignsTab';
import { ImagesTab } from './ImagesTab';

type Tab = 'campaigns' | 'images' | 'backups';

const TABS: Array<{ value: Tab; label: string }> = [
  { value: 'campaigns', label: 'Campaigns' },
  { value: 'images', label: 'Images' },
  { value: 'backups', label: 'Backups' },
];

export function Upgrades() {
  const [tab, setTab] = useState<Tab>('campaigns');

  return (
    <div>
      <div className="page-header">
        <h2 style={{ margin: 0 }}>Upgrades</h2>
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
        {tab === 'campaigns' && <CampaignsTab />}
        {tab === 'images' && <ImagesTab />}
        {tab === 'backups' && <BackupsTab />}
      </div>
    </div>
  );
}
