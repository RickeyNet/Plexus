import { useAuthStatus } from '@/api/auth';
import { PageHelp } from '@/components/PageHelp';
import { TabBar } from '@/components/TabBar';
import { visibleTabs } from '@/lib/tabGating';
import { usePathTab } from '@/lib/usePathTab';
import { Deployments } from '@/pages/Deployments/Deployments';
import { MaintenanceWindows } from '@/pages/MaintenanceWindows/MaintenanceWindows';
import { RiskAnalysis } from '@/pages/RiskAnalysis/RiskAnalysis';

type Tab = 'risk' | 'deployments' | 'maintenance';

// Maintenance windows ride on the deployments feature key.
const TABS: { key: Tab; label: string; feature: string }[] = [
  { key: 'risk', label: 'Risk Analysis', feature: 'risk-analysis' },
  { key: 'deployments', label: 'Deployments', feature: 'deployments' },
  { key: 'maintenance', label: 'Maintenance', feature: 'deployments' },
];
const TAB_KEYS = TABS.map((t) => t.key);

export function ChangeManagement() {
  const { data: auth } = useAuthStatus();
  const shownTabs = visibleTabs(TABS, auth);
  const [tab, selectTab] = usePathTab(
    '/change-management',
    TAB_KEYS,
    'risk',
    auth ? shownTabs.map((t) => t.key) : undefined,
  );

  return (
    <div>
      <PageHelp
        pageKey="change-management"
        title="Plan, Analyze & Deploy Changes"
        text="Assess risk before pushing changes, deploy with staged rollouts, and roll back if needed. The full change lifecycle in one place."
      />

      <TabBar tabs={shownTabs} active={tab} onChange={selectTab} aria-label="Change management sections" />

      {tab === 'risk' && (
        <>
          <PageHelp
            pageKey="change-management.risk"
            title="Pre-Change Risk Analysis"
            text="Score a proposed change before it ships. Compare candidate configs against the running baseline, flag impactful changes, and review which devices and interfaces would be affected."
          />
          <RiskAnalysis />
        </>
      )}
      {tab === 'deployments' && (
        <>
          <PageHelp
            pageKey="change-management.deployments"
            title="Staged Change Deployments"
            text="Push changes to devices in phases with built-in pause points. Track per-device outcome, roll back affected hosts on failure, and keep an audit trail of every step."
          />
          <Deployments />
        </>
      )}
      {tab === 'maintenance' && <MaintenanceWindows />}
    </div>
  );
}
