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

// The firmware upgrade tool - the Campaigns/Images/Backups sub-tab UI without
// an outer page heading. Rendered as the Upgrades tab of the Software page
// (/software/upgrades), under the page's own "Software" h2.
export function UpgradesContent() {
  const [tab, setTab] = useState<Tab>('campaigns');

  return (
    <div>
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
