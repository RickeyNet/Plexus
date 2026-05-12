import { useMemo, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';

import { useAuthStatus } from '@/api/auth';
import { PageHelp } from '@/components/PageHelp';
import { Deployments } from '@/pages/Deployments/Deployments';
import { RiskAnalysis } from '@/pages/RiskAnalysis/RiskAnalysis';

type Tab = 'risk' | 'deployments';

const TAB_QUERY_KEY = 'tab';

function readTab(search: string): Tab | null {
  const v = new URLSearchParams(search).get(TAB_QUERY_KEY);
  return v === 'risk' || v === 'deployments' ? v : null;
}

export function ChangeManagement() {
  const { data: auth } = useAuthStatus();
  const navigate = useNavigate();
  const { search } = useLocation();

  const isAdmin = auth?.role === 'admin';
  const access = useMemo(() => new Set(auth?.feature_access ?? []), [auth?.feature_access]);
  const canRisk = isAdmin || access.has('risk-analysis');
  const canDeploy = isAdmin || access.has('deployments');

  const queryTab = readTab(search);
  const defaultTab: Tab = canRisk ? 'risk' : 'deployments';
  const [tab, setTab] = useState<Tab>(queryTab ?? defaultTab);

  function selectTab(next: Tab) {
    setTab(next);
    navigate({ search: `?${TAB_QUERY_KEY}=${next}` }, { replace: true });
  }

  return (
    <div>
      <PageHelp
        pageKey="change-management"
        title="Plan, Analyze & Deploy Changes"
        text="Assess risk before pushing changes, deploy with staged rollouts, and roll back if needed. The full change lifecycle in one place."
      />

      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          marginBottom: '0.75rem',
          flexWrap: 'wrap',
        }}
      >
        {canRisk && (
          <button
            className={`btn btn-sm ${tab === 'risk' ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => selectTab('risk')}
          >
            Risk Analysis
          </button>
        )}
        {canDeploy && (
          <button
            className={`btn btn-sm ${tab === 'deployments' ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => selectTab('deployments')}
          >
            Deployments
          </button>
        )}
      </div>
      {tab === 'risk' && canRisk && (
        <>
          <PageHelp
            pageKey="change-management.risk"
            title="Pre-Change Risk Analysis"
            text="Score a proposed change before it ships. Compare candidate configs against the running baseline, flag impactful changes, and review which devices and interfaces would be affected."
          />
          <RiskAnalysis />
        </>
      )}
      {tab === 'deployments' && canDeploy && (
        <>
          <PageHelp
            pageKey="change-management.deployments"
            title="Staged Change Deployments"
            text="Push changes to devices in phases with built-in pause points. Track per-device outcome, roll back affected hosts on failure, and keep an audit trail of every step."
          />
          <Deployments />
        </>
      )}
    </div>
  );
}
