import type { CSSProperties } from 'react';

import type { MerakiSubnet } from '@/api/meraki';

import { hostAddress, type AppOption, type HostSuggestion } from './paths';

const OPTION_STYLE: CSSProperties = { padding: '0.4rem 0.65rem', cursor: 'pointer', fontSize: '0.85rem' };
const DETAIL_STYLE: CSSProperties = { fontSize: '0.75rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' };

/**
 * The hosts found for the name being typed in a subnet box, listed under it:
 * each resource with the DNS name that matched, its address and its network,
 * so the right one of several is picked with a click. After them, when given,
 * the internet applications or domains the text can be traced to as a
 * destination (`apps`). Rendered inside a `position: relative` wrapper around
 * the input.
 */
export function HostSuggestions({
  suggestions,
  onPick,
  apps = [],
  onPickApp,
}: {
  suggestions: HostSuggestion[];
  onPick: (host: MerakiSubnet) => void;
  apps?: AppOption[];
  onPickApp?: (name: string) => void;
}) {
  const shownApps = onPickApp ? apps : [];
  if (!suggestions.length && !shownApps.length) return null;
  return (
    <div
      role="listbox"
      aria-label={shownApps.length ? 'Hosts and internet applications matching the typed text' : 'Hosts matching the typed name'}
      style={{
        position: 'absolute',
        top: '100%',
        left: 0,
        zIndex: 10,
        minWidth: '100%',
        width: 'max-content',
        maxWidth: 'min(640px, 90vw)',
        maxHeight: 300,
        overflowY: 'auto',
        marginTop: '0.2rem',
        background: 'var(--card-bg)',
        border: '1px solid var(--border)',
        borderRadius: '0.3rem',
      }}
    >
      {suggestions.map(({ host, dnsName }) => (
        <div
          key={`${host.org_ref}|${host.node_id}|${host.cidr}`}
          role="option"
          aria-selected={false}
          // mousedown, not click: the input must not lose focus (and the list close) first.
          onMouseDown={(e) => { e.preventDefault(); onPick(host); }}
          style={OPTION_STYLE}
        >
          <div>
            {host.name} · {hostAddress(host)}
          </div>
          <div className="text-muted" style={DETAIL_STYLE}>
            {[dnsName, host.site_name].filter(Boolean).join(' · ')}
          </div>
        </div>
      ))}
      {shownApps.map((app) => (
        <div
          key={`app|${app.name}`}
          role="option"
          aria-selected={false}
          onMouseDown={(e) => { e.preventDefault(); onPickApp?.(app.name); }}
          style={OPTION_STYLE}
        >
          <div>{app.title}</div>
          <div className="text-muted" style={DETAIL_STYLE}>{app.detail}</div>
        </div>
      ))}
    </div>
  );
}
