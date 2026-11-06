import { useEffect, useRef } from 'react';

import type { TopologyStateCounts } from '@/api/dashboard';

import type { SourceHealthSummary } from './sourceHealth';

const RADIUS = 34;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

function isReducedMotion() {
  return document.body.classList.contains('reduced-motion');
}

interface RingProps {
  label: string;
  value: number;
  max: number;
  /** A second line under the label. */
  detail?: string;
  title?: string;
}

function Ring({ label, value, max, detail, title }: RingProps) {
  const valueRef = useRef<HTMLDivElement>(null);
  const ringRef = useRef<SVGCircleElement>(null);

  useEffect(() => {
    const valueEl = valueRef.current;
    const ringEl = ringRef.current;
    if (!valueEl || !ringEl) return;

    const clamped = Math.min(value, max);
    const ratio = max > 0 ? clamped / max : 0;
    const offset = CIRCUMFERENCE * (1 - ratio);

    ringEl.style.strokeDasharray = String(CIRCUMFERENCE);
    ringEl.style.strokeDashoffset = String(CIRCUMFERENCE);
    const ringRaf = requestAnimationFrame(() => {
      ringEl.style.strokeDashoffset = String(offset);
    });

    if (value === 0) {
      valueEl.textContent = '0';
      return () => cancelAnimationFrame(ringRaf);
    }
    if (isReducedMotion()) {
      valueEl.textContent = String(value);
      return () => cancelAnimationFrame(ringRaf);
    }

    const duration = 600;
    const start = performance.now();
    let counterRaf = 0;
    const step = (now: number) => {
      const progress = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      valueEl.textContent = String(Math.round(eased * value));
      if (progress < 1) counterRaf = requestAnimationFrame(step);
    };
    counterRaf = requestAnimationFrame(step);

    return () => {
      cancelAnimationFrame(ringRaf);
      cancelAnimationFrame(counterRaf);
    };
  }, [value, max]);

  return (
    <div className="stat-card stat-card-ring" title={title}>
      <div className="stat-ring-wrap">
        <svg className="stat-ring" viewBox="0 0 80 80">
          <circle className="stat-ring-bg" cx="40" cy="40" r={RADIUS} />
          <circle ref={ringRef} className="stat-ring-fill" cx="40" cy="40" r={RADIUS} />
        </svg>
        <div ref={valueRef} className="stat-ring-value">
          -
        </div>
      </div>
      <div className="stat-label">{label}</div>
      {detail && (
        <div className="text-muted" style={{ fontSize: '0.8rem', marginTop: '-0.75rem' }}>
          {detail}
        </div>
      )}
    </div>
  );
}

interface StatRingsProps {
  hosts: number;
  playbooks: number;
  jobs: number;
  /** Topology sources by health; omitted for users without the topology feature. */
  sources?: SourceHealthSummary;
  /** Integration entities by state, summed over providers; omitted without the monitoring feature. */
  entities?: TopologyStateCounts;
}

export function StatRings({ hosts, playbooks, jobs, sources, entities }: StatRingsProps) {
  const max = Math.max(hosts, playbooks, jobs, 1);
  const entityLine = entities
    ? `Entities ${entities.up} up / ${entities.degraded} degraded / ${entities.down} down`
    : undefined;
  return (
    <div className="stats-grid">
      <Ring label="Total Hosts" value={hosts} max={max} />
      <Ring label="Playbooks" value={playbooks} max={max} />
      <Ring label="Total Jobs" value={jobs} max={max} />
      {sources && sources.total > 0 && (
        // The ring fills with the healthy share of the sources.
        <Ring
          label="Sources Healthy"
          value={sources.healthy}
          max={sources.total}
          detail={[`${sources.healthy} of ${sources.total}`, entityLine].filter(Boolean).join(' · ')}
          title="Enabled topology sources (not demo) whose last collection succeeded, is recent and has no warnings"
        />
      )}
      {(!sources || sources.total === 0) && entities && entities.up + entities.degraded + entities.down > 0 && (
        // No sources to judge (or no topology feature): the entities alone.
        <Ring
          label="Entities Up"
          value={entities.up}
          max={entities.up + entities.degraded + entities.down}
          detail={entityLine}
          title="Devices, sites, uplinks, tunnels and cloud connections the integrations report"
        />
      )}
    </div>
  );
}
