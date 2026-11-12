import { useEffect, useRef, type ReactNode } from 'react';

import type { TopologyStateCounts } from '@/api/dashboard';

import { CountLink } from './CountLink';
import {
  ASSIGNMENTS_LINK,
  INVENTORY_LINK,
  TASKS_LINK,
  countNoun,
  type DashboardLinkAccess,
} from './dashboardLinks';
import { SOURCES_LINK, type SourceHealthSummary, topologyAvailabilityLink } from './sourceHealth';

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
  detail?: ReactNode;
  title?: string;
  /** Where the ring and its label link to (CountLink); plain when absent. */
  to?: string | null;
  /** Accessible name of that link, saying where it goes. */
  linkLabel?: string;
}

function Ring({ label, value, max, detail, title, to, linkLabel }: RingProps) {
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
      <CountLink to={to} label={linkLabel ?? `${label}: ${value}`} className="stat-ring-link">
        <div className="stat-ring-wrap">
          <svg className="stat-ring" viewBox="0 0 80 80" aria-hidden="true">
            <circle className="stat-ring-bg" cx="40" cy="40" r={RADIUS} />
            <circle ref={ringRef} className="stat-ring-fill" cx="40" cy="40" r={RADIUS} />
          </svg>
          <div ref={valueRef} className="stat-ring-value">
            -
          </div>
        </div>
        <div className="stat-label">{label}</div>
      </CountLink>
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
  /** Pages this user may open; a count of one they cannot stays plain. */
  access: DashboardLinkAccess;
}

const ENTITY_STATES = ['up', 'degraded', 'down'] as const;

/** "Entities 12 up / 1 degraded / 2 down", each non-zero count linking to those entities' availability. */
function EntityLine({ entities, linked }: { entities: TopologyStateCounts; linked: boolean }) {
  return (
    <>
      Entities{' '}
      {ENTITY_STATES.map((state, i) => (
        <span key={state}>
          {i > 0 && ' / '}
          <CountLink
            to={linked && entities[state] > 0 ? topologyAvailabilityLink(null, { state }) : null}
            label={`Show ${countNoun(entities[state], `${state} integration entity`, `${state} integration entities`)}`}
          >
            {entities[state]} {state}
          </CountLink>
        </span>
      ))}
    </>
  );
}

export function StatRings({ hosts, playbooks, jobs, sources, entities, access }: StatRingsProps) {
  const entityLine = entities ? <EntityLine entities={entities} linked={access.monitoring} /> : undefined;
  return (
    <div className="stats-grid">
      {/* Plain counts have no maximum: each ring is full when there is anything to count. */}
      {/* Totals link even at 0: the page they count is still the place to add some. */}
      <Ring
        label="Total Hosts"
        value={hosts}
        max={hosts}
        to={access.inventory ? INVENTORY_LINK : null}
        linkLabel={`Open Inventory: ${countNoun(hosts, 'host', 'hosts')}`}
      />
      <Ring
        label="Playbooks"
        value={playbooks}
        max={playbooks}
        to={access.playbooks ? TASKS_LINK : null}
        linkLabel={`Open Tasks: ${countNoun(playbooks, 'playbook', 'playbooks')}`}
      />
      <Ring
        label="Total Jobs"
        value={jobs}
        max={jobs}
        to={access.jobs ? ASSIGNMENTS_LINK : null}
        linkLabel={`Open Assignments: ${countNoun(jobs, 'job', 'jobs')}`}
      />
      {sources && sources.total > 0 && (
        // The ring fills with the healthy share of the sources. The Sources
        // dialog lists every source with its last collection; it has no
        // health filter, so the ring opens it unfiltered.
        <Ring
          label="Sources Healthy"
          value={sources.healthy}
          max={sources.total}
          to={access.topology ? SOURCES_LINK : null}
          linkLabel={`Open Sources: ${sources.healthy} of ${countNoun(sources.total, 'source', 'sources')} healthy`}
          detail={
            <>
              {sources.healthy} of {sources.total}
              {entityLine && <> · {entityLine}</>}
            </>
          }
          title="Enabled topology sources (not demo) whose last collection succeeded, is recent and has no warnings"
        />
      )}
      {(!sources || sources.total === 0) && entities && entities.up + entities.degraded + entities.down > 0 && (
        // No sources to judge (or no topology feature): the entities alone.
        <Ring
          label="Entities Up"
          value={entities.up}
          max={entities.up + entities.degraded + entities.down}
          to={access.monitoring && entities.up > 0 ? topologyAvailabilityLink(null, { state: 'up' }) : null}
          linkLabel={`Show ${countNoun(entities.up, 'up integration entity', 'up integration entities')}`}
          detail={entityLine}
          title="Devices, sites, uplinks, tunnels and cloud connections the integrations report"
        />
      )}
    </div>
  );
}
