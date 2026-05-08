import { useMemo, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';

import { useAuthStatus } from '@/api/auth';
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
      {tab === 'risk' && canRisk && <RiskAnalysis />}
      {tab === 'deployments' && canDeploy && <Deployments />}
    </div>
  );
}
