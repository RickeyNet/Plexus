import { useAwsReachability, type AwsReachability, type AwsReachabilityQuery, type ReachabilityStatus } from '@/api/meraki';

const VERDICT: Record<AwsReachability['verdict'], { label: string; color: string }> = {
  allowed: { label: 'AWS allows it', color: 'var(--success, #2f9e44)' },
  blocked: { label: 'AWS blocks it', color: 'var(--danger)' },
  partial: { label: 'AWS allows part of it', color: 'var(--warning, #f59f00)' },
  unknown: { label: 'AWS check incomplete', color: 'var(--warning, #f59f00)' },
};

const STEP: Record<ReachabilityStatus, { mark: string; color: string }> = {
  ok: { mark: '✓', color: 'var(--success, #2f9e44)' },
  blocked: { mark: '✕', color: 'var(--danger)' },
  partial: { mark: '◐', color: 'var(--warning, #f59f00)' },
  unknown: { mark: '?', color: 'var(--warning, #f59f00)' },
  info: { mark: 'i', color: 'var(--text-muted, #868e96)' },
};

/**
 * What the route tables, network ACLs and security groups of AWS do with the
 * traffic of one Path Mode leg: a verdict, and the steps behind it on demand.
 */
export function AwsPathCheck({ query }: { query: AwsReachabilityQuery }) {
  const check = useAwsReachability(query);
  if (check.isPending) return <div className="text-muted">Checking AWS route tables, network ACLs and security groups…</div>;
  if (check.error) return <div style={{ color: 'var(--danger)' }}>AWS check failed: {(check.error as Error).message}</div>;
  const result = check.data;
  if (!result?.applies) return null;
  const verdict = VERDICT[result.verdict];
  return (
    <details>
      <summary style={{ cursor: 'pointer' }}>
        <strong style={{ color: verdict.color }}>{verdict.label}</strong>
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
