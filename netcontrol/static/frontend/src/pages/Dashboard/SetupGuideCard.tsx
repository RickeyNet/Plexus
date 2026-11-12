import { useId } from 'react';
import { Link } from 'react-router';

import { useAddSource } from '@/components/AddSourceProvider-context';
import { Badge } from '@/components/Badge';
import { ProgressBar } from '@/components/ProgressBar';

import { type NotSetUpEntry, type SetupStep, setupProgress } from './setupGuide';

/** The first-run checklist: each step with why it matters and where to do it. */
export function SetupGuideCard({ steps, onDismiss }: { steps: SetupStep[]; onDismiss: () => void }) {
  const headingId = useId();
  const addSource = useAddSource();
  const { done, total } = setupProgress(steps);
  return (
    <section className="glass-card card dashboard-overview-card" aria-labelledby={headingId}>
      <div className="dashboard-overview-header">
        <h3 id={headingId} className="dashboard-overview-title">
          Get started with Plexus
        </h3>
        <div className="dashboard-setup-meta">
          <span className="text-muted">
            {done} of {total} done
          </span>
          <button type="button" className="btn btn-sm btn-ghost" onClick={onDismiss}>
            Hide guide
          </button>
        </div>
      </div>
      <ProgressBar value={total ? (done / total) * 100 : 0} tone="success" size="sm" label="Setup progress" />
      <ol className="dashboard-setup-steps">
        {steps.map((s, i) => (
          <li key={s.key} className={`dashboard-setup-step${s.done ? ' dashboard-setup-step-done' : ''}`}>
            <span className="dashboard-setup-mark" aria-hidden="true">
              {s.done ? '✓' : i + 1}
            </span>
            <div className="dashboard-setup-text">
              <strong>{s.title}</strong>
              <span className="text-muted">{s.why}</span>
            </div>
            {s.done ? (
              <Badge tone="success" size="sm">
                Done
              </Badge>
            ) : s.action.addSource && addSource.available ? (
              <button type="button" className="btn btn-sm btn-secondary" onClick={addSource.open}>
                {s.action.label}
              </button>
            ) : (
              <Link to={s.action.to} className="btn btn-sm btn-secondary">
                {s.action.label}
              </Link>
            )}
          </li>
        ))}
      </ol>
    </section>
  );
}

/** Stands in for the panels left out because what they need is not set up. */
export function NotSetUpCard({ entries }: { entries: NotSetUpEntry[] }) {
  const headingId = useId();
  return (
    <section className="glass-card card dashboard-overview-card" aria-labelledby={headingId}>
      <h3 id={headingId} className="dashboard-overview-title">
        Not set up yet
      </h3>
      <ul className="dashboard-setup-steps">
        {entries.map((e) => (
          <li key={e.key} className="dashboard-setup-step">
            <div className="dashboard-setup-text">
              <strong>{e.panels.join(', ')}</strong>
              <span className="text-muted">
                Needs: {e.needs}
                {!e.action && ' Ask an administrator to set it up.'}
              </span>
            </div>
            {e.action && (
              <Link to={e.action.to} className="btn btn-sm btn-secondary">
                {e.action.label}
              </Link>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}
