import { useState } from 'react';

import { TabBar } from '@/components/TabBar';

import { BackupsTab } from './BackupsTab';
import { CampaignsTab } from './CampaignsTab';
import { ImagesTab } from './ImagesTab';

type Tab = 'campaigns' | 'images' | 'backups';

const TABS: Array<{ key: Tab; label: string }> = [
  { key: 'campaigns', label: 'Campaigns' },
  { key: 'images', label: 'Images' },
  { key: 'backups', label: 'Backups' },
];

// The firmware upgrade tool - the Campaigns/Images/Backups sub-tab UI without
// an outer page heading. Rendered as the Upgrades tab of the Software page
// (/software/upgrades), under the page's own "Software" h2.
export function UpgradesContent() {
  const [tab, setTab] = useState<Tab>('campaigns');

  return (
    <div>
      <TabBar tabs={TABS} active={tab} onChange={setTab} size="sm" aria-label="Upgrade tool sections" />

      <div className="card" style={{ padding: '1rem' }}>
        {tab === 'campaigns' && <CampaignsTab />}
        {tab === 'images' && <ImagesTab />}
        {tab === 'backups' && <BackupsTab />}
      </div>
    </div>
  );
}
