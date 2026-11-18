import { useState } from 'react';

import { useAuthStatus } from '@/api/auth';
import { SegmentedControl } from '@/components/SegmentedControl';

import { IntendedContextsView } from './IntendedContextsView';
import { IntendedDevicesView } from './IntendedDevicesView';
import { IntendedIgnoresView } from './IntendedIgnoresView';
import { IntendedTemplatesView } from './IntendedTemplatesView';

type View = 'devices' | 'templates' | 'contexts' | 'ignores';
const VIEWS: { key: View; label: string; title: string }[] = [
  { key: 'devices', label: 'Devices', title: 'Each device’s intended configuration and its compliance' },
  { key: 'templates', label: 'Templates', title: 'Jinja2 templates scoped to devices' },
  { key: 'contexts', label: 'Contexts', title: 'JSON data merged into each device’s context' },
];
// Admins also manage the lines remediation leaves alone.
const ADMIN_VIEWS = [...VIEWS, { key: 'ignores' as const, label: 'Ignore rules', title: 'Lines remediation leaves alone' }];

/** The Configuration page's Intended tab: devices, templates and contexts behind a segmented control. */
export function IntendedTab() {
  const isAdmin = useAuthStatus().data?.role === 'admin';
  const [view, setView] = useState<View>('devices');
  return (
    <>
      <div className="toolbar">
        <SegmentedControl options={isAdmin ? ADMIN_VIEWS : VIEWS} value={view} onChange={setView} aria-label="Intended configuration view" />
      </div>
      {view === 'devices' && <IntendedDevicesView isAdmin={isAdmin} onShowTemplates={() => setView('templates')} />}
      {view === 'templates' && <IntendedTemplatesView isAdmin={isAdmin} />}
      {view === 'contexts' && <IntendedContextsView isAdmin={isAdmin} />}
      {view === 'ignores' && isAdmin && <IntendedIgnoresView />}
    </>
  );
}
