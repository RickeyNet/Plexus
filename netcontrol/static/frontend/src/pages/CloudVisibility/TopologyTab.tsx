import { useMemo, useState } from 'react';

import { type CloudConnection, type CloudResource, useCloudTopology } from '@/api/cloud';
import {
  attachmentBucketLabel,
  attachmentBucketTone,
  connectionMetadataSummary,
  formatCount,
  isAttachmentConnection,
  isGatewayResourceType,
  isRouteResourceType,
  providerLabel,
  resourceMetadataSummary,
  topologyLabel,
} from './helpers';
import type { CloudFilterState } from './CloudVisibility';

interface Props {
  filter: CloudFilterState;
}

type RouteFilter = 'all' | 'flagged' | 'public-egress' | 'hybrid-path';

interface RouteHighlight {
  tone: string;
  text: string;
}

interface LinkItem {
  label: string;
  tone: string;
  target: string;
  detail: string;
}

interface LinkGroup {
  label: string;
  tone: string;
  items: { target: string; detail: string }[];
}

interface RouteRow {
  uid: string;
  name: string;
  provider: string;
  type: string;
  destination: string;
  details: string;
  attachmentGroups: LinkGroup[];
  pathGroups: LinkGroup[];
  highlights: RouteHighlight[];
}

interface ProviderGroup {
  provider: string;
  resources: CloudResource[];
  connections: CloudConnection[];
  hybridLinks: { cloud_resource_uid?: string }[];
  routeRows?: RouteRow[];
}

function topologyConnectionLabel(connectionType: string | undefined, _provider: string, metadata: Record<string, unknown> | null | undefined): string {
  const n = String(connectionType ?? '').toLowerCase();
  if (n === 'route_table_association') {
    if (metadata && typeof metadata === 'object' && (metadata as Record<string, unknown>).subnet_name) return 'Attached Subnet';
    return 'Attached Network';
  }
  const labels: Record<string, string> = {
    route_next_hop: 'Next Hop',
    transit_gateway_attachment: 'Transit Gateway',
    direct_connect_gateway: 'Direct Connect',
    internet_gateway_attachment: 'Internet Gateway',
    expressroute_gateway: 'ExpressRoute',
    virtual_network_gateway_attachment: 'VNet Gateway',
    ipsec: 'IPsec Tunnel',
    router_attachment: 'Cloud Router',
    vpn_tunnel: 'HA VPN Tunnel',
    interconnect_attachment: 'Interconnect',
    vnet_peering: 'VNet Peering',
    vpc_peering: 'VPC Peering',
    security_boundary: 'Security Boundary',
  };
  return labels[n] ?? topologyLabel(n || connectionType || 'link');
}

function topologyResourceTypeLabel(t: string | undefined, provider: string | undefined): string {
  const n = String(t ?? '').toLowerCase();
  const pk = String(provider ?? '').toLowerCase();
  const labels: Record<string, string> = {
    route_table: 'Route Table',
    route_entry: 'Route Entry',
    transit_gateway: 'Transit Gateway',
    direct_connect: 'Direct Connect',
    internet_gateway: 'Internet Gateway',
    nat_gateway: 'NAT Gateway',
    expressroute: 'ExpressRoute',
    virtual_network_gateway: 'Virtual Network Gateway',
    local_network_gateway: 'Local Network Gateway',
    cloud_router: 'Cloud Router',
    ha_vpn_gateway: 'HA VPN Gateway',
    interconnect_attachment: pk === 'gcp' ? 'Interconnect Attachment' : 'Interconnect',
    vpn_tunnel: 'VPN Tunnel',
    vpc: 'VPC',
    vnet: 'VNet',
    security_group: 'Security Group',
    network_security_group: 'Network Security Group',
    firewall_policy: 'Firewall Policy',
  };
  return labels[n] ?? topologyLabel(n || t || 'resource');
}

function compactDetail(detail: string, duplicates: (string | undefined)[] = []): string {
  const dups = new Set(duplicates.map((v) => String(v ?? '').trim().toLowerCase()).filter(Boolean));
  const parts = String(detail ?? '')
    .split('|')
    .map((p) => p.trim())
    .filter(Boolean)
    .filter((p, i, all) => {
      const n = p.toLowerCase();
      return n && !dups.has(n) && all.findIndex((c) => c.toLowerCase() === n) === i;
    });
  return parts.join(' | ');
}

function groupLinkItems(items: LinkItem[]): LinkGroup[] {
  const groups = new Map<string, LinkGroup>();
  for (const item of items) {
    const label = item.label || 'Link';
    const tone = item.tone || 'info';
    const key = `${tone}:${label}`;
    let g = groups.get(key);
    if (!g) {
      g = { label, tone, items: [] };
      groups.set(key, g);
    }
    g.items.push({ target: item.target || '-', detail: item.detail || '' });
  }
  return [...groups.values()];
}

function looksPublicNextHop(value: unknown): boolean {
  const n = String(value ?? '').trim().toLowerCase();
  return n.includes('internet') || n.includes('nat') || n.includes('egress');
}

function isPublicRouteDestination(value: unknown): boolean {
  const n = String(value ?? '').trim().toLowerCase();
  return n.includes('0.0.0.0/0') || n.includes('::/0') || n === 'internet';
}

function isHybridConnectionType(t: unknown): boolean {
  const n = String(t ?? '').trim().toLowerCase();
  return n.includes('vpn') || n.includes('ipsec') || n.includes('expressroute') || n.includes('direct_connect') || n.includes('interconnect') || n.includes('router_attachment');
}

function isHybridResourceType(t: unknown): boolean {
  const n = String(t ?? '').trim().toLowerCase();
  return ['direct_connect', 'expressroute', 'virtual_network_gateway', 'local_network_gateway', 'ha_vpn_gateway', 'cloud_router', 'interconnect_attachment', 'vpn_gateway', 'vpn_tunnel'].includes(n);
}

function buildRouteRowsForGroup(group: ProviderGroup, lookup: Map<string, CloudResource>): RouteRow[] {
  return group.resources
    .filter((r) => isRouteResourceType(r.resource_type))
    .map((routeResource) => {
      const routeUid = String(routeResource.resource_uid ?? '');
      const destination = String(routeResource.cidr ?? '').trim();
      const incoming = group.connections.filter((c) => String(c.target_resource_uid ?? '') === routeUid);
      const outgoing = group.connections.filter((c) => String(c.source_resource_uid ?? '') === routeUid);

      const attachedTo: LinkItem[] = incoming.map((c) => {
        const sourceUid = String(c.source_resource_uid ?? '');
        const sourceResource = lookup.get(sourceUid);
        const detail = compactDetail(connectionMetadataSummary(c), [c.source_name, sourceResource?.name, destination]);
        return {
          label: topologyConnectionLabel(c.connection_type, group.provider, c.metadata as Record<string, unknown>),
          tone: attachmentBucketTone(attachmentBucketLabel(c.connection_type)),
          target: c.source_name || sourceResource?.name || sourceUid || '-',
          detail,
        };
      });

      const pathParts: LinkItem[] = outgoing.map((c) => {
        const targetUid = String(c.target_resource_uid ?? '');
        const targetResource = lookup.get(targetUid);
        const targetLabel = c.target_name || targetResource?.name || targetUid || '-';
        const detail = compactDetail(connectionMetadataSummary(c), [targetLabel, destination]);
        return {
          label: topologyConnectionLabel(c.connection_type, group.provider, c.metadata as Record<string, unknown>),
          tone: attachmentBucketTone(attachmentBucketLabel(c.connection_type)),
          target: targetLabel,
          detail,
        };
      });

      if (!pathParts.length) {
        const md = (routeResource.metadata && typeof routeResource.metadata === 'object'
          ? (routeResource.metadata as Record<string, unknown>)
          : {}) as Record<string, unknown>;
        if (md.next_hop) {
          pathParts.push({
            label: 'Next Hop',
            tone: 'secondary',
            target: String(md.next_hop),
            detail: md.destination ? String(md.destination) : '',
          });
        }
      }

      // Highlights
      const highlights: RouteHighlight[] = [];
      const md = (routeResource.metadata && typeof routeResource.metadata === 'object'
        ? (routeResource.metadata as Record<string, unknown>)
        : {}) as Record<string, unknown>;
      const hasPublicDest = isPublicRouteDestination(routeResource.cidr || md.destination || '');
      const hasPublicHop = outgoing.some((c) => {
        const tgt = lookup.get(String(c.target_resource_uid ?? ''));
        return (
          looksPublicNextHop(c.connection_type) ||
          looksPublicNextHop(c.target_name) ||
          looksPublicNextHop(tgt?.name) ||
          looksPublicNextHop(tgt?.resource_type) ||
          looksPublicNextHop((c.metadata as Record<string, unknown> | undefined)?.destination)
        );
      }) || looksPublicNextHop(md.next_hop);

      const hybridUids = new Set(group.hybridLinks.map((l) => String(l.cloud_resource_uid ?? '')).filter(Boolean));
      const hybridPath = group.connections.some((c) => {
        const src = String(c.source_resource_uid ?? '');
        const tgt = String(c.target_resource_uid ?? '');
        return (
          hybridUids.has(src) ||
          hybridUids.has(tgt) ||
          isHybridConnectionType(c.connection_type) ||
          isHybridResourceType(lookup.get(src)?.resource_type) ||
          isHybridResourceType(lookup.get(tgt)?.resource_type)
        );
      });

      if (hasPublicDest && hasPublicHop) highlights.push({ tone: 'warning', text: 'Public egress' });
      if (hybridPath) highlights.push({ tone: 'success', text: 'Hybrid path' });

      return {
        uid: routeUid,
        name: routeResource.name || routeUid || '-',
        provider: group.provider,
        type: String(routeResource.resource_type ?? ''),
        destination: routeResource.cidr || '-',
        details: resourceMetadataSummary(routeResource),
        attachmentGroups: groupLinkItems(attachedTo),
        pathGroups: groupLinkItems(pathParts),
        highlights,
      };
    });
}

export function TopologyTab({ filter }: Props) {
  const { data, isPending, error } = useCloudTopology({
    provider: filter.provider || undefined,
    account_id: filter.accountId,
  });
  const [routeFilter, setRouteFilter] = useState<RouteFilter>('all');

  const resources = useMemo(() => data?.resources ?? [], [data?.resources]);
  const connections = useMemo(() => data?.connections ?? [], [data?.connections]);
  const hybridLinks = useMemo(() => data?.hybrid_links ?? [], [data?.hybrid_links]);
  const summary = data?.summary ?? {};

  const lookup = useMemo(() => {
    const m = new Map<string, CloudResource>();
    for (const r of resources) {
      const uid = String(r.resource_uid ?? '');
      if (uid) m.set(uid, r);
    }
    return m;
  }, [resources]);

  const providerGroups = useMemo<ProviderGroup[]>(() => {
    const ps = new Set<string>();
    resources.forEach((r) => r.provider && ps.add(String(r.provider).toLowerCase()));
    connections.forEach((c) => c.provider && ps.add(String(c.provider).toLowerCase()));
    hybridLinks.forEach((l) => l.provider && ps.add(String(l.provider).toLowerCase()));
    return [...ps].sort().map((provider) => ({
      provider,
      resources: resources.filter((r) => String(r.provider ?? '').toLowerCase() === provider),
      connections: connections.filter((c) => String(c.provider ?? '').toLowerCase() === provider),
      hybridLinks: hybridLinks.filter((l) => String(l.provider ?? '').toLowerCase() === provider),
    }));
  }, [resources, connections, hybridLinks]);

  const routeGroups = useMemo<ProviderGroup[]>(
    () =>
      providerGroups
        .map((g) => ({ ...g, routeRows: buildRouteRowsForGroup(g, lookup) }))
        .filter((g) => g.routeRows && g.routeRows.length),
    [providerGroups, lookup],
  );

  const routeMatches = (row: RouteRow): boolean => {
    if (routeFilter === 'flagged') return row.highlights.length > 0;
    if (routeFilter === 'public-egress') return row.highlights.some((h) => h.text.toLowerCase() === 'public egress');
    if (routeFilter === 'hybrid-path') return row.highlights.some((h) => h.text.toLowerCase() === 'hybrid path');
    return true;
  };

  const filteredRouteGroups = routeGroups
    .map((g) => ({ ...g, routeRows: (g.routeRows ?? []).filter(routeMatches) }))
    .filter((g) => g.routeRows && g.routeRows.length);

  const totalRouteRows = routeGroups.reduce((s, g) => s + (g.routeRows?.length ?? 0), 0);
  const filteredRouteRows = filteredRouteGroups.reduce((s, g) => s + (g.routeRows?.length ?? 0), 0);

  const routeResourceCount = resources.filter((r) => isRouteResourceType(r.resource_type)).length;
  const gatewayResourceCount = resources.filter((r) => isGatewayResourceType(r.resource_type)).length;
  const attachmentLinkCount = connections.filter((c) => isAttachmentConnection(c.connection_type)).length;

  if (isPending) return <div className="text-muted">Loading topology…</div>;
  if (error) return <div style={{ color: 'var(--danger)' }}>Error: {(error as Error).message}</div>;

  return (
    <div>
      <div className="drift-summary-grid" style={{ marginBottom: '0.75rem' }}>
        <SummaryCard label="Accounts" value={summary.account_count ?? 0} />
        <SummaryCard label="Cloud Resources" value={summary.resource_count ?? 0} />
        <SummaryCard label="Cloud Links" value={summary.connection_count ?? 0} />
        <SummaryCard label="Route Objects" value={routeResourceCount} />
        <SummaryCard label="Gateways" value={gatewayResourceCount} />
        <SummaryCard label="Attachment Links" value={attachmentLinkCount} />
        <SummaryCard label="Hybrid Links" value={summary.hybrid_link_count ?? 0} />
      </div>

      {providerGroups.length > 0 && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '0.75rem', marginBottom: '0.75rem' }}>
          {providerGroups.map((g) => {
            const routeCount = g.resources.filter((r) => isRouteResourceType(r.resource_type)).length;
            const gatewayCount = g.resources.filter((r) => isGatewayResourceType(r.resource_type)).length;
            const buckets = new Map<string, number>();
            g.connections
              .filter((c) => isAttachmentConnection(c.connection_type))
              .forEach((c) => {
                const label = attachmentBucketLabel(c.connection_type);
                buckets.set(label, (buckets.get(label) ?? 0) + 1);
              });
            return (
              <div key={g.provider} className="card" style={{ padding: '0.85rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.5rem' }}>
                  <strong>{providerLabel(g.provider)}</strong>
                  <span className="text-muted" style={{ fontSize: '0.8rem' }}>
                    {formatCount(g.resources.length)} resources / {formatCount(g.connections.length)} links
                  </span>
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                  {routeCount > 0 && <span className="badge badge-info">{routeCount} route objects</span>}
                  {gatewayCount > 0 && <span className="badge badge-success">{gatewayCount} gateways</span>}
                  {g.hybridLinks.length > 0 && <span className="badge badge-secondary">{g.hybridLinks.length} hybrid links</span>}
                  {[...buckets.entries()]
                    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
                    .map(([label, count]) => (
                      <span key={label} className={`badge badge-${attachmentBucketTone(label)}`}>
                        {count} {label.toLowerCase()}
                      </span>
                    ))}
                  {!routeCount && !gatewayCount && !g.hybridLinks.length && !buckets.size && (
                    <span className="text-muted">No route or attachment details</span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {routeGroups.length > 0 && (
        <div className="card" style={{ padding: '0.85rem', marginBottom: '0.75rem' }}>
          <div style={{ display: 'flex', alignItems: 'end', justifyContent: 'space-between', gap: '0.75rem', flexWrap: 'wrap' }}>
            <label style={{ minWidth: 220, margin: 0 }}>
              Route Focus
              <select className="form-select" value={routeFilter} onChange={(e) => setRouteFilter(e.target.value as RouteFilter)}>
                <option value="all">All routes</option>
                <option value="flagged">Flagged routes</option>
                <option value="public-egress">Public egress</option>
                <option value="hybrid-path">Hybrid path</option>
              </select>
            </label>
            <div className="text-muted" style={{ fontSize: '0.85rem' }}>
              Showing {formatCount(filteredRouteRows)} of {formatCount(totalRouteRows)} route objects
            </div>
          </div>
        </div>
      )}

      {filteredRouteGroups.length > 0 ? (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '0.75rem', marginBottom: '1rem' }}>
          {filteredRouteGroups.map((g) => (
            <div key={g.provider} className="card" style={{ padding: '0.85rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.5rem' }}>
                <strong>{providerLabel(g.provider)} Route Paths</strong>
                <span className="text-muted" style={{ fontSize: '0.8rem' }}>{formatCount(g.routeRows?.length ?? 0)} route objects</span>
              </div>
              <table className="chart-table">
                <thead>
                  <tr>
                    <th>Route Object</th>
                    <th>Attached To</th>
                    <th>Path</th>
                  </tr>
                </thead>
                <tbody>
                  {(g.routeRows ?? []).map((row) => (
                    <tr key={row.uid}>
                      <td>
                        {row.name}
                        <div className="text-muted" style={{ fontSize: '0.75rem' }}>
                          {topologyResourceTypeLabel(row.type, row.provider)} | {row.destination}
                        </div>
                        <div className="text-muted" style={{ fontSize: '0.75rem', marginTop: '0.2rem' }}>{row.details}</div>
                      </td>
                      <td>
                        <LinkGroups groups={row.attachmentGroups} emptyLabel="No route associations" />
                      </td>
                      <td>
                        {row.highlights.length > 0 && (
                          <div style={{ marginBottom: '0.35rem' }}>
                            {row.highlights.map((h, i) => (
                              <span key={i} className={`badge badge-${h.tone}`} style={{ marginRight: '0.35rem' }}>{h.text}</span>
                            ))}
                          </div>
                        )}
                        <LinkGroups groups={row.pathGroups} emptyLabel="No route path details available" />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
        </div>
      ) : routeGroups.length > 0 ? (
        <div className="card" style={{ padding: '1rem', marginBottom: '0.75rem' }}>
          <p className="text-muted" style={{ margin: 0 }}>No route objects match the current topology filter.</p>
        </div>
      ) : null}

      <h4 style={{ margin: '0.5rem 0 0.45rem' }}>Resources</h4>
      {!resources.length ? (
        <div className="card" style={{ padding: '1rem', marginBottom: '0.75rem' }}>
          <p className="text-muted" style={{ margin: 0 }}>No cloud resources yet. Run discovery on an account.</p>
        </div>
      ) : (
        <div style={{ overflowX: 'auto', marginBottom: '0.75rem' }}>
          <table className="chart-table">
            <thead>
              <tr>
                <th>Provider</th><th>Type</th><th>Name</th><th>Region</th><th>CIDR</th><th>Status</th><th>Details</th>
              </tr>
            </thead>
            <tbody>
              {resources.map((r) => (
                <tr key={`${r.provider}-${r.resource_uid}`}>
                  <td>{providerLabel(r.provider)}</td>
                  <td>{r.resource_type ?? ''}</td>
                  <td>{r.name || r.resource_uid}</td>
                  <td>{r.region ?? '-'}</td>
                  <td>{r.cidr ?? '-'}</td>
                  <td>{r.status ?? '-'}</td>
                  <td>{resourceMetadataSummary(r)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h4 style={{ margin: '0.5rem 0 0.45rem' }}>Connections</h4>
      {!connections.length ? (
        <div className="card" style={{ padding: '1rem', marginBottom: '0.75rem' }}>
          <p className="text-muted" style={{ margin: 0 }}>No cloud-to-cloud links available.</p>
        </div>
      ) : (
        <div style={{ overflowX: 'auto', marginBottom: '0.75rem' }}>
          <table className="chart-table">
            <thead>
              <tr>
                <th>Provider</th><th>From</th><th>To</th><th>Type</th><th>State</th><th>Details</th>
              </tr>
            </thead>
            <tbody>
              {connections.map((c, i) => (
                <tr key={i}>
                  <td>{providerLabel(c.provider)}</td>
                  <td>{c.source_name || c.source_resource_uid || ''}</td>
                  <td>{c.target_name || c.target_resource_uid || ''}</td>
                  <td>{c.connection_type ?? ''}</td>
                  <td>{c.state ?? '-'}</td>
                  <td>{connectionMetadataSummary(c)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h4 style={{ margin: '0.5rem 0 0.45rem' }}>Hybrid Links</h4>
      {!hybridLinks.length ? (
        <div className="card" style={{ padding: '1rem' }}>
          <p className="text-muted" style={{ margin: 0 }}>No on-prem to cloud links mapped yet.</p>
        </div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table className="chart-table">
            <thead>
              <tr>
                <th>On-Prem Host</th><th>Cloud Resource</th><th>Type</th><th>State</th>
              </tr>
            </thead>
            <tbody>
              {hybridLinks.map((l, i) => (
                <tr key={i}>
                  <td>{l.host_hostname || l.host_label || '-'}</td>
                  <td>{l.cloud_resource_name || l.cloud_resource_uid || '-'}</td>
                  <td>{l.connection_type ?? ''}</td>
                  <td>{l.state ?? '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function SummaryCard({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="drift-summary-card">
      <div className="drift-summary-value">{value}</div>
      <div className="drift-summary-label">{label}</div>
    </div>
  );
}

function LinkGroups({ groups, emptyLabel }: { groups: LinkGroup[]; emptyLabel: string }) {
  if (!groups.length) return <span className="text-muted">{emptyLabel}</span>;
  return (
    <>
      {groups.map((g, i) => (
        <div key={i} style={{ marginBottom: '0.45rem' }}>
          <div>
            <span className={`badge badge-${g.tone}`} style={{ marginRight: '0.35rem', marginBottom: '0.35rem' }}>{g.label}</span>
          </div>
          {g.items.map((item, j) => (
            <div key={j} style={{ paddingLeft: '0.15rem', marginTop: '0.1rem' }}>
              <div>{item.target}</div>
              {item.detail && <div className="text-muted" style={{ fontSize: '0.75rem' }}>{item.detail}</div>}
            </div>
          ))}
        </div>
      ))}
    </>
  );
}
