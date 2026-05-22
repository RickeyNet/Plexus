import { useMemo, useState } from 'react';

import { useCloudPolicyEffective, useCloudPolicyRules } from '@/api/cloud';
import type { CloudFilterState } from './CloudVisibility';
import { formatCount, providerLabel } from './helpers';

interface Props {
  filter: CloudFilterState;
}

type Exposure = 'all' | 'public';

function isPublicRule(rule: { direction?: string; source_selector?: string; destination_selector?: string }): boolean {
  const direction = String(rule.direction ?? '').toLowerCase();
  const src = String(rule.source_selector ?? '').toLowerCase();
  const dst = String(rule.destination_selector ?? '').toLowerCase();
  const inboundPublic = direction === 'inbound' && (src.includes('0.0.0.0/0') || src.includes('::/0') || src === 'any');
  const outboundPublic = direction === 'outbound' && (dst.includes('0.0.0.0/0') || dst.includes('::/0') || dst === 'any');
  return inboundPublic || outboundPublic;
}

export function PolicyTab({ filter }: Props) {
  const [exposure, setExposure] = useState<Exposure>('all');
  const [direction, setDirection] = useState('');
  const [action, setAction] = useState('');
  const [selectedUid, setSelectedUid] = useState<string>('');
  const [selectedName, setSelectedName] = useState<string>('');

  const params = {
    provider: filter.provider || undefined,
    account_id: filter.accountId,
    direction: direction || undefined,
    action: action || undefined,
    resource_uid: selectedUid || undefined,
  };

  const effective = useCloudPolicyEffective(params);
  const rulesQuery = useCloudPolicyRules({ ...params, limit: 200 });

  const allViews = useMemo(() => effective.data?.resources ?? [], [effective.data?.resources]);
  const allRules = useMemo(() => rulesQuery.data?.rules ?? [], [rulesQuery.data?.rules]);

  const views = useMemo(() => {
    if (exposure !== 'public') return allViews;
    return allViews.filter((row) => Number(row.public_ingress_count ?? 0) > 0 || Number(row.open_egress_count ?? 0) > 0);
  }, [allViews, exposure]);

  const rules = useMemo(() => {
    if (exposure !== 'public') return allRules;
    return allRules.filter(isPublicRule);
  }, [allRules, exposure]);

  const totals = views.reduce(
    (acc, row) => {
      acc.resources += 1;
      acc.rules += Number(row.rule_count ?? 0);
      acc.publicIngress += Number(row.public_ingress_count ?? 0);
      acc.openEgress += Number(row.open_egress_count ?? 0);
      acc.denies += Number(row.deny_count ?? 0);
      return acc;
    },
    { resources: 0, rules: 0, publicIngress: 0, openEgress: 0, denies: 0 },
  );

  function selectResource(uid: string, name: string) {
    setSelectedUid(uid);
    setSelectedName(name);
  }

  function clearSelection() {
    setSelectedUid('');
    setSelectedName('');
  }

  return (
    <div>
      <div className="card" style={{ padding: '0.9rem', marginBottom: '0.75rem' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.75rem', alignItems: 'end' }}>
          <label>Exposure Filter
            <select className="form-select" value={exposure} onChange={(e) => setExposure(e.target.value as Exposure)}>
              <option value="all">All Policy Resources</option>
              <option value="public">Public Exposure Only</option>
            </select>
          </label>
          <label>Direction Filter
            <select className="form-select" value={direction} onChange={(e) => setDirection(e.target.value)}>
              <option value="">All Directions</option>
              <option value="inbound">Inbound</option>
              <option value="outbound">Outbound</option>
            </select>
          </label>
          <label>Action Filter
            <select className="form-select" value={action} onChange={(e) => setAction(e.target.value)}>
              <option value="">All Actions</option>
              <option value="allow">Allow</option>
              <option value="deny">Deny</option>
            </select>
          </label>
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
            <button className="btn btn-secondary" onClick={clearSelection} disabled={!selectedUid}>Clear Drilldown</button>
            <div className="text-muted" style={{ fontSize: '0.9em' }}>
              {selectedUid ? <>Drilldown: <strong>{selectedName || selectedUid}</strong></> : 'Click "View Rules" to drill into a resource.'}
            </div>
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1rem' }}>
        <div>
          <h4 style={{ margin: '0 0 0.45rem' }}>Effective Policy Views</h4>
          {effective.isPending && <div className="text-muted">Loading…</div>}
          {effective.error && <div style={{ color: 'var(--danger)' }}>Error: {(effective.error as Error).message}</div>}
          {!views.length ? (
            <div className="card" style={{ padding: '1rem' }}>
              <p className="text-muted" style={{ margin: 0 }}>No effective cloud policy views available for current filters.</p>
            </div>
          ) : (
            <>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: '0.75rem', marginBottom: '0.75rem' }}>
                <Stat label="Policy Resources" value={formatCount(totals.resources)} />
                <Stat label="Rules" value={formatCount(totals.rules)} />
                <Stat label="Public Ingress" value={formatCount(totals.publicIngress)} />
                <Stat label="Open Egress" value={formatCount(totals.openEgress)} />
                <Stat label="Deny Rules" value={formatCount(totals.denies)} />
              </div>
              <div style={{ overflowX: 'auto' }}>
                <table className="chart-table">
                  <thead>
                    <tr><th>Resource</th><th>Provider</th><th>Rules</th><th>Public Ingress</th><th>Open Egress</th><th>Deny</th><th></th></tr>
                  </thead>
                  <tbody>
                    {views.map((row) => {
                      const highlighted = Number(row.public_ingress_count ?? 0) > 0 || Number(row.open_egress_count ?? 0) > 0;
                      const selected = selectedUid && row.resource_uid === selectedUid;
                      const bg = selected
                        ? 'rgba(25,118,210,0.14)'
                        : highlighted
                          ? 'rgba(255,145,0,0.12)'
                          : undefined;
                      return (
                        <tr key={row.resource_uid} style={bg ? { background: bg } : undefined}>
                          <td>
                            {row.resource_name || row.resource_uid || '-'}
                            <div className="text-muted" style={{ fontSize: '0.75rem' }}>{row.resource_type ?? ''}</div>
                          </td>
                          <td>{providerLabel(row.provider)}</td>
                          <td>{formatCount(row.rule_count)}</td>
                          <td>{formatCount(row.public_ingress_count)}</td>
                          <td>{formatCount(row.open_egress_count)}</td>
                          <td>{formatCount(row.deny_count)}</td>
                          <td>
                            <button
                              className="btn btn-sm btn-secondary"
                              onClick={() => selectResource(row.resource_uid ?? '', row.resource_name ?? row.resource_uid ?? '')}
                            >
                              {selected ? 'Selected' : 'View Rules'}
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>

        <div>
          <h4 style={{ margin: '0 0 0.45rem' }}>Rule Inventory</h4>
          {rulesQuery.isPending && <div className="text-muted">Loading…</div>}
          {rulesQuery.error && <div style={{ color: 'var(--danger)' }}>Error: {(rulesQuery.error as Error).message}</div>}
          {!rules.length ? (
            <div className="card" style={{ padding: '1rem' }}>
              <p className="text-muted" style={{ margin: 0 }}>No cloud policy rules discovered yet. Run discovery for a cloud account to populate security-group, NSG, or firewall rules.</p>
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="chart-table">
                <thead>
                  <tr><th>Resource</th><th>Rule</th><th>Direction</th><th>Action</th><th>Protocol / Ports</th><th>Selectors</th></tr>
                </thead>
                <tbody>
                  {rules.map((row, i) => {
                    const highlighted = isPublicRule(row);
                    return (
                      <tr key={i} style={highlighted ? { background: 'rgba(255,145,0,0.12)' } : undefined}>
                        <td>
                          {row.resource_name || row.resource_uid || '-'}
                          <div className="text-muted" style={{ fontSize: '0.75rem' }}>{providerLabel(row.provider)}</div>
                        </td>
                        <td>
                          {row.rule_name || row.rule_uid || '-'}
                          <div className="text-muted" style={{ fontSize: '0.75rem' }}>Priority: {row.priority ?? '-'}</div>
                        </td>
                        <td>{row.direction ?? '-'}</td>
                        <td>{row.action ?? '-'}</td>
                        <td>
                          {(row.protocol ?? 'all').toUpperCase()}
                          <div className="text-muted" style={{ fontSize: '0.75rem' }}>{row.port_expression ?? 'all'}</div>
                        </td>
                        <td>
                          <div className="text-muted" style={{ fontSize: '0.75rem' }}>Src</div>
                          {row.source_selector ?? '-'}
                          <div className="text-muted" style={{ fontSize: '0.75rem', marginTop: '0.35rem' }}>Dst</div>
                          {row.destination_selector ?? '-'}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="card" style={{ padding: '0.75rem' }}>
      <div className="text-muted" style={{ fontSize: '0.75rem' }}>{label}</div>
      <div style={{ fontSize: '1.35rem', fontWeight: 700 }}>{value}</div>
    </div>
  );
}
