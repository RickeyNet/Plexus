import { useState } from 'react';

import { useAuthStatus } from '@/api/auth';
import { SegmentedControl } from '@/components/SegmentedControl';

import { IntendedContextsView } from './IntendedContextsView';
import { IntendedDevicesView } from './IntendedDevicesView';
import { IntendedTemplatesView } from './IntendedTemplatesView';

type View = 'devices' | 'templates' | 'contexts';
const VIEWS: { key: View; label: string; title: string }[] = [
  { key: 'devices', label: 'Devices', title: 'Each device’s intended configuration and its compliance' },
  { key: 'templates', label: 'Templates', title: 'Jinja2 templates scoped to devices' },
  { key: 'contexts', label: 'Contexts', title: 'JSON data merged into each device’s context' },
];

/** The Configuration page's Intended tab: devices, templates and contexts behind a segmented control. */
export function IntendedTab() {
  const isAdmin = useAuthStatus().data?.role === 'admin';
  const [view, setView] = useState<View>('devices');
  return (
    <>
      <div className="toolbar">
        <SegmentedControl options={VIEWS} value={view} onChange={setView} aria-label="Intended configuration view" />
      </div>
      {view === 'devices' && <IntendedDevicesView isAdmin={isAdmin} onShowTemplates={() => setView('templates')} />}
      {view === 'templates' && <IntendedTemplatesView isAdmin={isAdmin} />}
      {view === 'contexts' && <IntendedContextsView isAdmin={isAdmin} />}
    </>
  );
}
