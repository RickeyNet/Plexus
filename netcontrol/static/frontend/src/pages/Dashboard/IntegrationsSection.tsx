import { useId, useMemo } from 'react';
import { Link } from 'react-router';

import type { TopologySourceTypeCounts } from '@/api/dashboard';
import type { TopologySource } from '@/api/meraki';
import { useAddSource } from '@/components/AddSourceProvider-context';
import { Badge } from '@/components/Badge';
import { formatBackendDateTime, formatRelativeTime } from '@/lib/datetime';

import { CountLink } from './CountLink';
import {
  HEALTH_DISPLAY,
  type EntityTypeCounts,
  type IntegrationCard,
  buildIntegrationCards,
  describeCounts,
} from './integrationCards';
import {
  SOURCES_LINK,
  type AvailabilitySourceRef,
  type AvailabilityStateFilter,
  topologyAvailabilityLink,
} from './sourceHealth';

interface Props {
  /** GET /api/topology/sources; undefined while it loads. */
  sources?: readonly TopologySource[];
  /** `topology.by_source` of /api/dashboard; undefined without the monitoring feature. */
  bySource?: readonly TopologySourceTypeCounts[];
}

/**
 * One card per connected integration source: collection health, the state of
 * what it collects per entity type, and links to its map and availability.
 * Renders nothing once the sources are known and none is connected.
 */
export function IntegrationsSection({ sources, bySource }: Props) {
  const headingId = useId();
  const addSource = useAddSource();
  const cards = useMemo(() => (sources ? buildIntegrationCards(sources, bySource) : null), [sources, bySource]);
  if (cards && cards.length === 0) return null;
  return (
    <section className="glass-card card dashboard-overview-card" aria-labelledby={headingId} aria-busy={!cards}>
      <div className="dashboard-overview-header">
        <h3 id={headingId} className="dashboard-overview-title">
          Integrations
        </h3>
        <div className="dashboard-setup-meta">
          {addSource.available && (
            <button type="button" className="btn btn-sm btn-ghost" onClick={addSource.open}>
              Add source
            </button>
          )}
          <Link to={SOURCES_LINK} className="dashboard-overview-link">
            Sources
          </Link>
        </div>
      </div>
      {cards ? (
        <div className="dashboard-integrations-grid">
          {cards.map((c) => (
            <IntegrationCardView key={c.key} card={c} />
          ))}
        </div>
      ) : (
        <div className="dashboard-integrations-grid">
          <div className="skeleton skeleton-card" />
          <div className="skeleton skeleton-card" />
        </div>
      )}
    </section>
  );
}

function IntegrationCardView({ card }: { card: IntegrationCard }) {
  const headingId = useId();
  const { source, health, counts } = card;
  const display = HEALTH_DISPLAY[health];
  const showMessage = (health === 'failed' || health === 'partial') && source.message;
  return (
    <article className="dashboard-integration" aria-labelledby={headingId}>
      <div className="dashboard-integration-head">
        <h4 id={headingId} className="dashboard-integration-name" title={source.name}>
          {source.name || card.typeLabel}
        </h4>
        <Badge tone={display.tone} size="sm" solid={health === 'failed'}>
          {display.label}
        </Badge>
      </div>
      <div className="dashboard-integration-meta text-muted">
        {card.typeLabel}
        {source.last_collected_at && (
          <>
            {' · '}
            <span title={formatBackendDateTime(source.last_collected_at)}>
              collected {formatRelativeTime(source.last_collected_at)}
            </span>
          </>
        )}
      </div>
      {showMessage && (
        <div className="dashboard-integration-message text-muted" title={source.message}>
          {source.message}
        </div>
      )}

      {health === 'never' ? (
        <p className="dashboard-integration-empty text-muted">
          Not collected yet. <Link to={card.sourcesLink}>Collect it from Sources</Link>
        </p>
      ) : counts && counts.length === 0 ? (
        <p className="dashboard-integration-empty text-muted">No availability tracked for this source yet.</p>
      ) : counts ? (
        <>
          <ul className="dashboard-integration-types">
            {counts.map((c) => (
              <EntityTypeRow key={c.type} counts={c} source={card.availabilityRef} sourceName={source.name || card.typeLabel} />
            ))}
          </ul>
          {card.combinedAccounts > 1 && (
            <p className="dashboard-integration-note text-muted">
              Combined for all {card.combinedAccounts} {card.typeLabel} accounts.
            </p>
          )}
        </>
      ) : (
        source.detail && <p className="dashboard-integration-empty text-muted">{source.detail}</p>
      )}

      <div className="dashboard-integration-links">
        <Link to={card.mapLink} className="dashboard-overview-link">
          Map
        </Link>
        {card.availabilityLink && (
          <Link to={card.availabilityLink} className="dashboard-overview-link">
            Availability
          </Link>
        )}
      </div>
    </article>
  );
}

// Down and degraded lead with a mark and a word, so they read without colour.
// Each count opens Monitoring -> Availability filtered to this source, type
// and state (plain when the card has no availability link).
function EntityTypeRow({
  counts: c,
  source,
  sourceName,
}: {
  counts: EntityTypeCounts;
  source: AvailabilitySourceRef | null;
  sourceName: string;
}) {
  const link = (state?: AvailabilityStateFilter) =>
    source ? topologyAvailabilityLink(source, { entityType: c.type, state }) : null;
  const label = (n: number, state: string) =>
    `Show ${n} ${state ? `${state} ` : ''}${c.label.toLowerCase()} of ${sourceName}`;
  return (
    <li className="dashboard-integration-type" title={`${c.label}: ${describeCounts(c)}`}>
      <CountLink to={link()} label={label(c.total, '')} className="dashboard-integration-type-label">
        {c.label} <span className="text-muted">{c.total}</span>
      </CountLink>
      <span className="dashboard-integration-states">
        {c.down > 0 && (
          <CountLink to={link('down')} label={label(c.down, 'down')}>
            <Badge tone="danger" solid size="sm">
              <span aria-hidden="true">▼ </span>
              {c.down} down
            </Badge>
          </CountLink>
        )}
        {c.degraded > 0 && (
          <CountLink to={link('degraded')} label={label(c.degraded, 'degraded')}>
            <Badge tone="warning" size="sm">
              <span aria-hidden="true">! </span>
              {c.degraded} degraded
            </Badge>
          </CountLink>
        )}
        {c.up > 0 && (
          <CountLink to={link('up')} label={label(c.up, 'up')}>
            <Badge tone="success" size="sm">
              {c.up} up
            </Badge>
          </CountLink>
        )}
        {c.unknown > 0 && (
          <CountLink to={link('unknown')} label={label(c.unknown, 'unknown')}>
            <Badge tone="neutral" size="sm">
              {c.unknown} unknown
            </Badge>
          </CountLink>
        )}
      </span>
    </li>
  );
}
