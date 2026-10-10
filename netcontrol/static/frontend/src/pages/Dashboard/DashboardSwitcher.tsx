import { Link, useNavigate } from 'react-router';

import { useCustomDashboards } from '@/api/dashboard';

// Shared across the overview (/), the custom-dashboard list (/dashboards) and
// the viewer (/dashboards/:id): one select that jumps between the built-in
// overview and every custom dashboard, plus a link to manage them. Before this
// the list page had no inbound link at all.
const MANAGE = '__manage__';

interface Props {
  /** The custom dashboard being viewed, or null for the overview / list. */
  current: number | null;
}

export function DashboardSwitcher({ current }: Props) {
  const navigate = useNavigate();
  const { data: dashboards = [] } = useCustomDashboards();

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
      <select
        className="form-select"
        aria-label="Switch dashboard"
        value={current ?? ''}
        onChange={(e) => {
          const v = e.target.value;
          if (v === '') navigate('/');
          else if (v === MANAGE) navigate('/dashboards');
          else navigate(`/dashboards/${v}`);
        }}
      >
        <option value="">Overview</option>
        {dashboards.map((d) => (
          <option key={d.id} value={d.id}>
            {d.name}
          </option>
        ))}
        <option value={MANAGE}>Manage dashboards…</option>
      </select>
      <Link to="/dashboards" className="btn btn-sm btn-secondary">
        Manage
      </Link>
    </div>
  );
}
