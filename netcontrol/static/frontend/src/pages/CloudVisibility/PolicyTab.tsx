import { useId, useMemo, useState } from 'react';

import { useCloudPolicyEffective, useCloudPolicyRules } from '@/api/cloud';
import { Callout } from '@/components/Callout';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { StatGrid, StatTile } from '@/components/StatTile';
import { useShowMore } from '@/lib/useShowMore';
import type { CloudFilterState } from './CloudVisibility';
import { formatCount, isPublicRule, policyRuleKeys, providerLabel, topologyResourceTypeLabel } from './helpers';

interface Props {
  filter: CloudFilterState;
}

type Exposure = 'all' | 'public';

/** The most rules GET /api/cloud/policies/rules returns in one request (its `limit` maximum). */
const RULES_LIMIT = 2000;

const EXPOSED_ROW_STYLE = { background: 'rgba(from var(--warning) r g b / 0.12)' };
const SELECTED_ROW_STYLE = { background: 'var(--primary-soft)' };
const SUBTEXT_STYLE = { fontSize: 'var(--text-xs)' };

const DISCOVERY_HINT =
  'Run discovery on an account, subscription or project to read its security groups, NSGs or firewall rules.';

interface Selection {
  uid: string;
  name: string;
}

export function PolicyTab({ filter }: Props) {
  const fid = useId();
  const [exposure, setExposure] = useState<Exposure>('all');
  const [direction, setDirection] = useState('');
  const [action, setAction] = useState('');
  const [selected, setSelected] = useState<Selection | null>(null);

  // The views endpoint only filters by provider and account; direction,
  // action and the drilldown narrow the rule inventory alone.
  const scope = { provider: filter.provider || undefined, account_id: filter.accountId };
  const effective = useCloudPolicyEffective(scope);
  const rulesQuery = useCloudPolicyRules({
    ...scope,
    direction: direction || undefined,
    action: action || undefined,
    resource_uid: selected?.uid || undefined,
    limit: RULES_LIMIT,
  });

  return (
    <div className="stack">
      <div className="toolbar" style={{ alignItems: 'flex-end' }}>
        <div className="form-group" style={{ marginBottom: 0 }}>
          <label className="form-label" htmlFor={`${fid}-exposure`}>Exposure</label>
          <select id={`${fid}-exposure`} className="form-select" value={exposure} onChange={(e) => setExposure(e.target.value as Exposure)}>
            <option value="all">All policy resources</option>
            <option value="public">Public exposure only</option>
          </select>
        </div>
        <div className="form-group" style={{ marginBottom: 0 }}>
          <label className="form-label" htmlFor={`${fid}-direction`}>Direction</label>
          <select id={`${fid}-direction`} className="form-select" value={direction} onChange={(e) => setDirection(e.target.value)}>
            <option value="">All directions</option>
            <option value="inbound">Inbound</option>
            <option value="outbound">Outbound</option>
          </select>
        </div>
        <div className="form-group" style={{ marginBottom: 0 }}>
          <label className="form-label" htmlFor={`${fid}-action`}>Action</label>
          <select id={`${fid}-action`} className="form-select" value={action} onChange={(e) => setAction(e.target.value)}>
            <option value="">All actions</option>
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
          </select>
        </div>
      </div>

      <section className="stack stack-sm">
        <h3 style={{ margin: 0 }}>Effective policy views</h3>
        <EffectiveViews query={effective} exposure={exposure} selectedUid={selected?.uid ?? ''} onSelect={setSelected} />
      </section>

      <section className="stack stack-sm">
        <div className="toolbar">
          <h3 style={{ margin: 0 }}>Rule inventory</h3>
          {selected ? (
            <>
              <span className="text-muted">
                Resource: <strong>{selected.name || selected.uid}</strong>
              </span>
              <button type="button" className="btn btn-sm btn-secondary" onClick={() => setSelected(null)}>
                Clear
              </button>
            </>
          ) : (
            <span className="text-muted">Use View rules on a resource to see only its rules.</span>
          )}
        </div>
        <RuleInventory
          query={rulesQuery}
          exposure={exposure}
          serverFiltered={Boolean(direction || action || selected)}
        />
      </section>
    </div>
  );
}

interface EffectiveViewsProps {
  query: ReturnType<typeof useCloudPolicyEffective>;
  exposure: Exposure;
  selectedUid: string;
  onSelect: (selection: Selection) => void;
}

function EffectiveViews({ query, exposure, selectedUid, onSelect }: EffectiveViewsProps) {
  const allViews = useMemo(() => query.data?.resources ?? [], [query.data?.resources]);
  const views = useMemo(() => {
    if (exposure !== 'public') return allViews;
    return allViews.filter((row) => Number(row.public_ingress_count ?? 0) > 0 || Number(row.open_egress_count ?? 0) > 0);
  }, [allViews, exposure]);

  if (query.isError && !query.data) return <QueryError what="effective policy views" query={query} />;
  if (query.isPending) return <LoadingState />;
  if (!allViews.length) return <EmptyState message="No policy resources yet." description={DISCOVERY_HINT} />;
  if (!views.length) {
    return (
      <EmptyState
        message="No policy resources with public exposure."
        description="Set Exposure to All policy resources to see every resource."
      />
    );
  }

  const totals = views.reduce(
    (acc, row) => {
      acc.rules += Number(row.rule_count ?? 0);
      acc.publicIngress += Number(row.public_ingress_count ?? 0);
      acc.openEgress += Number(row.open_egress_count ?? 0);
      acc.denies += Number(row.deny_count ?? 0);
      return acc;
    },
    { rules: 0, publicIngress: 0, openEgress: 0, denies: 0 },
  );

  return (
    <>
      <StatGrid compact>
        <StatTile label="Policy Resources" value={formatCount(views.length)} />
        <StatTile label="Rules" value={formatCount(totals.rules)} />
        <StatTile label="Public Ingress" value={formatCount(totals.publicIngress)} />
        <StatTile label="Open Egress" value={formatCount(totals.openEgress)} />
        <StatTile label="Deny Rules" value={formatCount(totals.denies)} />
      </StatGrid>
      <div style={{ overflowX: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr><th>Resource</th><th>Provider</th><th>Rules</th><th>Public ingress</th><th>Open egress</th><th>Deny</th><th></th></tr>
          </thead>
          <tbody>
            {views.map((row) => {
              const uid = row.resource_uid ?? '';
              const isSelected = Boolean(selectedUid) && uid === selectedUid;
              const exposed = Number(row.public_ingress_count ?? 0) > 0 || Number(row.open_egress_count ?? 0) > 0;
              const style = isSelected ? SELECTED_ROW_STYLE : exposed ? EXPOSED_ROW_STYLE : undefined;
              return (
                <tr key={uid} style={style}>
                  <td>
                    {row.resource_name || uid || '-'}
                    <div className="text-muted" style={SUBTEXT_STYLE}>{topologyResourceTypeLabel(row.resource_type, row.provider)}</div>
                  </td>
                  <td>{providerLabel(row.provider)}</td>
                  <td>{formatCount(row.rule_count)}</td>
                  <td>{formatCount(row.public_ingress_count)}</td>
                  <td>{formatCount(row.open_egress_count)}</td>
                  <td>{formatCount(row.deny_count)}</td>
                  <td>
                    <button
                      type="button"
                      className="btn btn-sm btn-secondary"
                      aria-pressed={isSelected}
                      onClick={() => onSelect({ uid, name: row.resource_name || uid })}
                    >
                      {isSelected ? 'Selected' : 'View rules'}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}

interface RuleInventoryProps {
  query: ReturnType<typeof useCloudPolicyRules>;
  exposure: Exposure;
  /** Direction, action or a resource drilldown narrowed the request. */
  serverFiltered: boolean;
}

function RuleInventory({ query, exposure, serverFiltered }: RuleInventoryProps) {
  const allRules = useMemo(() => query.data?.rules ?? [], [query.data?.rules]);
  const rules = useMemo(() => (exposure === 'public' ? allRules.filter(isPublicRule) : allRules), [allRules, exposure]);
  const keys = useMemo(() => policyRuleKeys(rules), [rules]);
  const { visible, hiddenCount, showMore } = useShowMore(rules);

  if (query.isError && !query.data) return <QueryError what="policy rules" query={query} />;
  if (query.isPending) return <LoadingState />;
  if (!allRules.length) {
    return serverFiltered ? (
      <EmptyState
        message="No policy rules match the current filters."
        description="Change the direction or action filter, or clear the resource drilldown."
      />
    ) : (
      <EmptyState message="No policy rules yet." description={DISCOVERY_HINT} />
    );
  }
  if (!rules.length) {
    return (
      <EmptyState
        message="No public-exposure rules match the current filters."
        description="Set Exposure to All policy resources to see every rule."
      />
    );
  }

  return (
    <>
      {allRules.length >= RULES_LIMIT && (
        <Callout tone="warning" role="note" title={`Only the first ${formatCount(RULES_LIMIT)} rules were loaded.`}>
          More rules exist than one request returns. Narrow the list with the direction or action filter, or pick a
          resource with View rules.
        </Callout>
      )}
      <div style={{ overflowX: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr><th>Resource</th><th>Rule</th><th>Direction</th><th>Action</th><th>Protocol / ports</th><th>Selectors</th></tr>
          </thead>
          <tbody>
            {visible.map((row, i) => (
              <tr key={keys[i]} style={isPublicRule(row) ? EXPOSED_ROW_STYLE : undefined}>
                <td>
                  {row.resource_name || row.resource_uid || '-'}
                  <div className="text-muted" style={SUBTEXT_STYLE}>{providerLabel(row.provider)}</div>
                </td>
                <td>
                  {row.rule_name || row.rule_uid || '-'}
                  <div className="text-muted" style={SUBTEXT_STYLE}>Priority: {row.priority ?? '-'}</div>
                </td>
                <td>{row.direction ?? '-'}</td>
                <td>{row.action ?? '-'}</td>
                <td>
                  {(row.protocol ?? 'all').toUpperCase()}
                  <div className="text-muted" style={SUBTEXT_STYLE}>{row.port_expression ?? 'all'}</div>
                </td>
                <td>
                  <div className="text-muted" style={SUBTEXT_STYLE}>Src</div>
                  {row.source_selector ?? '-'}
                  <div className="text-muted" style={{ ...SUBTEXT_STYLE, marginTop: 'var(--space-1)' }}>Dst</div>
                  {row.destination_selector ?? '-'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="toolbar">
        <span className="text-muted">
          Showing {formatCount(visible.length)} of {formatCount(rules.length)} rules
        </span>
        {hiddenCount > 0 && (
          <button type="button" className="btn btn-sm btn-secondary" onClick={showMore}>
            Show more ({hiddenCount.toLocaleString()} hidden)
          </button>
        )}
      </div>
    </>
  );
}
