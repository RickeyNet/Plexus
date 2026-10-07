import { useCloudReachability, type CloudReachability, type CloudReachabilityQuery, type ReachabilityStatus } from '@/api/meraki';

import { providerLabel } from './helpers';
import { CLOUD_CHECKS } from './paths';

const VERDICT: Record<CloudReachability['verdict'], { label: (cloud: string) => string; color: string }> = {
  allowed: { label: (cloud) => `${cloud} allows it`, color: 'var(--success, #2f9e44)' },
  blocked: { label: (cloud) => `${cloud} blocks it`, color: 'var(--danger)' },
  partial: { label: (cloud) => `${cloud} allows part of it`, color: 'var(--warning, #f59f00)' },
  unknown: { label: (cloud) => `${cloud} check incomplete`, color: 'var(--warning, #f59f00)' },
};

const STEP: Record<ReachabilityStatus, { mark: string; color: string }> = {
  ok: { mark: '✓', color: 'var(--success, #2f9e44)' },
  blocked: { mark: '✕', color: 'var(--danger)' },
  partial: { mark: '◐', color: 'var(--warning, #f59f00)' },
  unknown: { mark: '?', color: 'var(--warning, #f59f00)' },
  info: { mark: 'i', color: 'var(--text-muted, #868e96)' },
};

/**
 * What the routing and filtering of a cloud do with the traffic of one Path
 * Mode leg: a verdict, and the steps behind it on demand.
 */
export function CloudPathCheck({ query }: { query: CloudReachabilityQuery }) {
  const check = useCloudReachability(query);
  const cloud = providerLabel(query.cloud);
  if (check.isPending) return <div className="text-muted">Checking {CLOUD_CHECKS[query.cloud]}…</div>;
  if (check.error) return <div style={{ color: 'var(--danger)' }}>{cloud} check failed: {(check.error as Error).message}</div>;
  const result = check.data;
  if (!result) return null;
  // Asked because an end looked like it was in the cloud: say why it was not checked.
  if (!result.applies) return <div className="text-muted">ⓘ No {cloud} check: {result.summary}</div>;
  const verdict = VERDICT[result.verdict];
  return (
    <details>
      <summary style={{ cursor: 'pointer' }}>
        <strong style={{ color: verdict.color }}>{verdict.label(cloud)}</strong>
        {result.traffic ? <span className="text-muted"> ({result.traffic})</span> : null}: {result.summary}
      </summary>
      {(['forward', 'return'] as const).map((direction) => {
        const steps = result.steps.filter((s) => s.direction === direction);
        if (!steps.length) return null;
        return (
          <div key={direction} style={{ margin: '0.25rem 0 0 1rem' }}>
            <div className="text-muted">
              {direction === 'forward' ? `${query.source} → ${query.destination}` : `Replies, ${query.destination} → ${query.source}`}
            </div>
            {steps.map((step) => (
              <div key={`${step.stage}|${step.where}|${step.text}`} style={{ display: 'flex', gap: '0.4rem' }}>
                <span aria-label={step.status} style={{ color: STEP[step.status].color, minWidth: '1em', textAlign: 'center' }}>
                  {STEP[step.status].mark}
                </span>
                <span>
                  <strong>{step.where}:</strong> {step.text}
                </span>
              </div>
            ))}
          </div>
        );
      })}
    </details>
  );
}
