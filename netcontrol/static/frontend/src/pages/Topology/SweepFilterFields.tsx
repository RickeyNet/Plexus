import { FIELD_STYLE, NOTE_STYLE, providerLabel } from './helpers';
import { SWEEP_KINDS, vlanTextError, type SweepFilters, type SweepSourceOption } from './sweep';

// The filter block of the sweep's source (or destination) networks, shared by
// the Reachability and Summarize tabs.

const BLOCK_STYLE = { border: 'none', padding: 0, margin: '0.75rem 0 0', minWidth: 0 } as const;
const BLOCK_TITLE_STYLE = { fontWeight: 600, padding: 0 } as const;

/** The list with `value` added, or removed when it is there. */
function toggle<T>(list: T[], value: T): T[] {
  return list.includes(value) ? list.filter((v) => v !== value) : [...list, value];
}

interface FilterFieldsProps {
  title: string;
  /** Prefix of the element ids, unique per block. */
  idPrefix: string;
  filters: SweepFilters;
  onChange: (patch: Partial<SweepFilters>) => void;
  sources: SweepSourceOption[];
  providers: string[];
  /** Dimmed and not editable (a side's block while that side's end is typed). */
  disabled?: boolean;
  note?: string;
}

/** The filters of one side of a sweep: which source (or destination) networks are kept. */
export function FilterFields({ title, idPrefix, filters, onChange, sources, providers, disabled, note }: FilterFieldsProps) {
  const vlanError = vlanTextError(filters.vlans);
  const titleId = `${idPrefix}-title`;
  return (
    <fieldset
      disabled={disabled}
      aria-labelledby={titleId}
      style={{ ...BLOCK_STYLE, opacity: disabled ? 0.55 : undefined }}
    >
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', alignItems: 'baseline' }}>
        <span id={titleId} style={BLOCK_TITLE_STYLE}>{title}</span>
        {note && <span className="text-muted" style={NOTE_STYLE}>{note}</span>}
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginTop: '0.4rem', alignItems: 'flex-start' }}>
        <label style={FIELD_STYLE}>
          <span className="form-label">Sources</span>
          <select
            className="form-select"
            multiple
            size={Math.min(5, Math.max(2, sources.length))}
            value={filters.sources.map(String)}
            onChange={(e) => onChange({ sources: [...e.target.selectedOptions].map((o) => Number(o.value)) })}
            title="None selected: all sources. Ctrl+click to pick several."
          >
            {sources.map((s) => (
              <option key={s.key} value={s.id}>{s.label}</option>
            ))}
          </select>
          <span className="text-muted" style={NOTE_STYLE}>
            {filters.sources.length ? `${filters.sources.length} selected` : 'All sources'}
          </span>
        </label>
        <fieldset style={{ ...FIELD_STYLE, border: 'none', padding: 0, margin: 0 }}>
          <span className="form-label">Providers</span>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, auto)', gap: '0.1rem 0.75rem' }}>
            {providers.map((p) => (
              <label key={p} style={{ display: 'flex', gap: '0.3rem', alignItems: 'center' }}>
                <input
                  type="checkbox"
                  checked={filters.providers.includes(p)}
                  onChange={() => onChange({ providers: toggle(filters.providers, p) })}
                />
                {providerLabel(p)}
              </label>
            ))}
          </div>
          <span className="text-muted" style={NOTE_STYLE}>None checked: every provider</span>
        </fieldset>
        <fieldset style={{ ...FIELD_STYLE, border: 'none', padding: 0, margin: 0 }}>
          <span className="form-label">Kinds of network</span>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, auto)', gap: '0.1rem 0.75rem' }}>
            {SWEEP_KINDS.map((k) => (
              <label key={k.key} style={{ display: 'flex', gap: '0.3rem', alignItems: 'center' }}>
                <input
                  type="checkbox"
                  checked={filters.kinds.includes(k.key)}
                  onChange={() => onChange({ kinds: toggle(filters.kinds, k.key) })}
                />
                {k.label}
              </label>
            ))}
          </div>
        </fieldset>
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginTop: '0.75rem', alignItems: 'flex-end' }}>
        <label style={FIELD_STYLE}>
          <span className="form-label">VLANs</span>
          <input
            className="form-input"
            placeholder="100, 110-120"
            value={filters.vlans}
            onChange={(e) => onChange({ vlans: e.target.value })}
            style={vlanError ? { borderColor: 'var(--danger)' } : undefined}
            title={vlanError ?? 'VLAN ids and ranges'}
          />
        </label>
        <label style={FIELD_STYLE}>
          <span className="form-label">Name contains</span>
          <input
            className="form-input"
            placeholder="user, data or /^VLAN 1\d\d /"
            value={filters.name}
            onChange={(e) => onChange({ name: e.target.value })}
          />
        </label>
        <label style={FIELD_STYLE}>
          <span className="form-label">Exclude</span>
          <input
            className="form-input"
            placeholder="voice, guest, printer"
            value={filters.exclude}
            onChange={(e) => onChange({ exclude: e.target.value })}
          />
        </label>
        <label style={FIELD_STYLE}>
          <span className="form-label">Sites</span>
          <input
            className="form-input"
            placeholder="branch, /^store \d+$/"
            value={filters.sites}
            onChange={(e) => onChange({ sites: e.target.value })}
          />
        </label>
        <label style={FIELD_STYLE}>
          <span className="form-label">Within</span>
          <input
            className="form-input"
            placeholder="10.0.0.0/8, 172.16.0.0/12"
            value={filters.within}
            onChange={(e) => onChange({ within: e.target.value })}
          />
        </label>
        <label style={FIELD_STYLE}>
          <span className="form-label">Overlapping</span>
          <input
            className="form-input"
            placeholder="10.64.0.0/16, 172.17.0.0/16"
            value={filters.overlaps}
            onChange={(e) => onChange({ overlaps: e.target.value })}
            title="Networks that overlap one of these ranges, wider ones included"
          />
        </label>
        <label style={{ ...FIELD_STYLE, minWidth: 120 }}>
          <span className="form-label">In VPN</span>
          <select
            className="form-select"
            value={filters.inVpn}
            onChange={(e) => onChange({ inVpn: e.target.value as SweepFilters['inVpn'] })}
          >
            <option value="">Any</option>
            <option value="1">Advertised</option>
            <option value="0">Not advertised</option>
          </select>
        </label>
      </div>
    </fieldset>
  );
}
