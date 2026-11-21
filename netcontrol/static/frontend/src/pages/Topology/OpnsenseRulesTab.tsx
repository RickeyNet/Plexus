import { useId, useMemo, useState } from 'react';

import { useHostConfigBackups } from '@/api/host-details';
import {
  type OpnsenseAnalyzedRule,
  type OpnsenseLogEvidence,
  type OpnsenseRuleFlag,
  type OpnsenseRulesView,
  useOpnsenseRules,
  useOpnsenseRulesDiff,
} from '@/api/opnsenseRules';
import { Badge } from '@/components/Badge';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { SegmentedControl } from '@/components/SegmentedControl';
import { formatBackendDateTime } from '@/lib/datetime';

import { evidenceStatus, evidenceText, evidenceTone, flowText, passBlockText } from './filterlogEvidence';
import { DETAIL_CELL_STYLE, SCROLL_X_STYLE } from './helpers';
import {
  actionTone,
  aliasTableLines,
  changeText,
  countersText,
  endpointText,
  FLAG_LABELS,
  FLAG_TONES,
  filterRules,
  flagLabel,
  type RuleFilter,
} from './opnsenseRules';

const FLAGS = Object.keys(FLAG_LABELS) as OpnsenseRuleFlag[];
const FLOATING = '*';

/**
 * The Rules tab of an OPNsense firewall in the device details panel: the
 * flag counts of its newest config.xml backup, the flagged rules, and the
 * full rule view and backup-to-backup diff in a wide modal.
 */
export function OpnsenseRulesTab({ hostId }: { hostId: number }) {
  const q = useOpnsenseRules(hostId);
  const [open, setOpen] = useState(false);

  if (q.isPending) return <LoadingState />;
  if (q.error) {
    return <EmptyState compact message="Rules not available" description={(q.error as Error).message} />;
  }
  const view = q.data;
  if (!view.available) return <EmptyState compact message="No rules to show" description={view.message} />;
  const flagged = view.rules.filter((r) => r.flags.some((f) => f !== 'disabled'));
  const logged = view.rules.filter((r) => r.log_evidence).length;
  const logStatus = evidenceStatus(view.log_evidence);

  return (
    <div className="stack stack-sm" style={{ fontSize: '0.78rem' }}>
      <div className="text-muted" style={{ fontSize: '0.72rem' }}>
        {view.summary.rules} rules · backup {formatBackendDateTime(view.backup?.captured_at, '-')}
        {view.stats_collected_at
          ? ` · counters ${formatBackendDateTime(view.stats_collected_at, '-')}`
          : ' · no rule counters collected'}
      </div>
      {logStatus && (
        <div className="text-muted" style={{ fontSize: '0.72rem' }}>
          {logStatus}
          {view.log_evidence?.received_at
            ? ` ${logged} rules and ${view.log_evidence.unmatched.length} automatic or unknown rules logged in ${view.log_evidence.window_hours} h.`
            : ''}
        </div>
      )}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.3rem' }}>
        {FLAGS.map((flag) => (
          <Badge key={flag} size="sm" tone={view.summary[flag] ? FLAG_TONES[flag] : 'neutral'}>
            {FLAG_LABELS[flag]}: {view.summary[flag]}
          </Badge>
        ))}
      </div>
      {flagged.length === 0 ? (
        <p className="text-muted">No rule is flagged.</p>
      ) : (
        <div style={SCROLL_X_STYLE}>
          <table className="data-table" style={{ fontSize: '0.75rem' }}>
            <thead>
              <tr>
                <th style={DETAIL_CELL_STYLE}>#</th>
                <th style={DETAIL_CELL_STYLE}>Rule</th>
                <th style={DETAIL_CELL_STYLE}>Flags</th>
              </tr>
            </thead>
            <tbody>
              {flagged.slice(0, 12).map((rule) => (
                <tr key={rule.key}>
                  <td style={DETAIL_CELL_STYLE}>{rule.number}</td>
                  <td style={DETAIL_CELL_STYLE}>{rule.description || `${rule.action} ${endpointText(rule.destination)}`}</td>
                  <td style={DETAIL_CELL_STYLE}>
                    <FlagBadges rule={rule} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div>
        <button type="button" className="btn btn-secondary btn-sm" onClick={() => setOpen(true)}>
          Open rules and changes
        </button>
      </div>
      <Modal isOpen={open} onClose={() => setOpen(false)} title={`Firewall rules — ${view.host}`} size="large">
        <RulesModalBody hostId={hostId} view={view} />
      </Modal>
    </div>
  );
}

function FlagBadges({ rule }: { rule: OpnsenseAnalyzedRule }) {
  if (!rule.flags.length) return null;
  return (
    <span style={{ display: 'inline-flex', flexWrap: 'wrap', gap: '0.2rem' }}>
      {rule.flags.map((flag) => (
        <Badge key={flag} size="sm" tone={FLAG_TONES[flag]}>
          {flagLabel(rule, flag)}
        </Badge>
      ))}
    </span>
  );
}

type View = 'rules' | 'changes';

function RulesModalBody({ hostId, view }: { hostId: number; view: OpnsenseRulesView }) {
  const [tab, setTab] = useState<View>('rules');
  return (
    <div className="stack">
      <SegmentedControl
        aria-label="Rules view"
        options={[
          { key: 'rules', label: 'Rules' },
          { key: 'changes', label: 'Changes between backups' },
        ]}
        value={tab}
        onChange={setTab}
      />
      {tab === 'rules' ? <RulesTable view={view} /> : <RulesDiff hostId={hostId} newest={view.backup?.id ?? null} />}
    </div>
  );
}

function RulesTable({ view }: { view: OpnsenseRulesView }) {
  const ids = useId();
  const [filter, setFilter] = useState<RuleFilter>({ iface: '', flag: '', text: '' });
  const shown = useMemo(() => filterRules(view.rules, filter), [view.rules, filter]);
  const groups = useMemo(() => {
    // The interfaces, then what rules name that is no interface (enc0, openvpn, a group's members).
    const known = view.interfaces.map((i) => i.key);
    const extra = view.rules.flatMap((r) => r.zones).filter((z) => z !== FLOATING && !known.includes(z));
    const keys = filter.iface ? [filter.iface] : [...new Set([...known, ...extra])];
    const found = keys.map((key) => ({
      key,
      label: interfaceLabel(view, key),
      rules: shown.filter((r) => r.zones.includes(key)),
    }));
    // Floating rules on every interface, once.
    const everywhere = shown.filter((r) => r.zones.includes(FLOATING));
    if (everywhere.length) found.unshift({ key: FLOATING, label: 'Every interface (floating)', rules: everywhere });
    return found.filter((g) => g.rules.length);
  }, [shown, view, filter.iface]);

  return (
    <div className="stack stack-sm">
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-3)', alignItems: 'flex-end' }}>
        <div className="form-group" style={{ margin: 0 }}>
          <label htmlFor={`${ids}-iface`}>Interface</label>
          <select
            id={`${ids}-iface`}
            className="form-select"
            value={filter.iface}
            onChange={(e) => setFilter({ ...filter, iface: e.target.value })}
          >
            <option value="">All interfaces</option>
            {view.interfaces.map((i) => (
              <option key={i.key} value={i.key}>
                {interfaceLabel(view, i.key)}
              </option>
            ))}
          </select>
        </div>
        <div className="form-group" style={{ margin: 0 }}>
          <label htmlFor={`${ids}-text`}>Search</label>
          <input
            id={`${ids}-text`}
            className="form-input"
            value={filter.text}
            placeholder="e.g. 443 or WebServers"
            onChange={(e) => setFilter({ ...filter, text: e.target.value })}
          />
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.3rem' }} role="group" aria-label="Show only">
          {FLAGS.map((flag) => (
            <Badge
              key={flag}
              tone={FLAG_TONES[flag]}
              pressed={filter.flag === flag}
              onClick={() => setFilter({ ...filter, flag: filter.flag === flag ? '' : flag })}
            >
              {FLAG_LABELS[flag]} ({view.summary[flag]})
            </Badge>
          ))}
        </div>
      </div>
      <div className="text-muted" style={{ fontSize: '0.78rem' }}>
        Rules are listed in the order the firewall evaluates them; # is the number a path trace names.
        {view.stats_available ? '' : ' No rule counters were collected, so no rule is flagged unused.'}
        {view.alias_tables?.read_at
          ? ` Aliases marked "pf table" are resolved by path traces from their table as read at ${formatBackendDateTime(view.alias_tables.read_at, '-')}.`
          : ''}
      </div>
      {groups.length === 0 ? (
        <EmptyState compact message="No rule matches the filters" />
      ) : (
        groups.map((group) => (
          <div key={group.key}>
            <h4 style={{ margin: 'var(--space-3) 0 var(--space-2)', fontSize: 'var(--text-base)' }}>{group.label}</h4>
            <div style={SCROLL_X_STYLE}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Action</th>
                    <th>Dir</th>
                    <th>Proto</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Description</th>
                    <th>Counters</th>
                    <th>Log ({view.log_evidence?.window_hours ?? 24} h)</th>
                    <th>Flags</th>
                  </tr>
                </thead>
                <tbody>
                  {group.rules.map((rule) => (
                    <tr key={rule.key} style={rule.disabled ? { opacity: 0.6 } : undefined}>
                      <td>{rule.number}</td>
                      <td>
                        <Badge size="sm" tone={actionTone(rule.action)}>
                          {rule.action}
                        </Badge>
                        {rule.quick ? '' : <span className="text-muted"> (not quick)</span>}
                      </td>
                      <td>{rule.direction}</td>
                      <td>
                        {rule.protocol} <span className="text-muted">{rule.family}</span>
                      </td>
                      <td title={rule.source.cidrs.join(', ')}>
                        {endpointText(rule.source)}
                        <AliasTables lines={aliasTableLines(rule.source, view.alias_tables)} />
                      </td>
                      <td title={rule.destination.cidrs.join(', ')}>
                        {endpointText(rule.destination)}
                        <AliasTables lines={aliasTableLines(rule.destination, view.alias_tables)} />
                      </td>
                      <td>
                        {rule.description}
                        {rule.gateway && <div className="text-muted">gateway {rule.gateway}</div>}
                        {rule.tier !== 'interface' && <div className="text-muted">{rule.tier} rule</div>}
                      </td>
                      <td>{countersText(rule) || <span className="text-muted">-</span>}</td>
                      <td>
                        <LogEvidenceCell evidence={rule.log_evidence ?? null} view={view} logs={rule.log} />
                      </td>
                      <td>
                        <FlagBadges rule={rule} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ))
      )}
      <UnmatchedEvidence view={view} />
      {view.notes.length > 0 && (
        <div className="text-muted" style={{ fontSize: '0.78rem' }}>
          Not read from the configuration: {view.notes.join('; ')}.
        </div>
      )}
    </div>
  );
}

/** The aliases of a rule side the path trace resolves from the collected pf tables. */
function AliasTables({ lines }: { lines: string[] }) {
  if (!lines.length) return null;
  return (
    <>
      {lines.map((line) => (
        <div key={line} className="text-muted" style={{ fontSize: '0.72rem' }}>
          {line}
        </div>
      ))}
    </>
  );
}

/** A rule's firewall log evidence in the rules table: its counts, the details and flows on hover. */
function LogEvidenceCell({
  evidence,
  view,
  logs,
}: {
  evidence: OpnsenseLogEvidence | null;
  view: OpnsenseRulesView;
  logs: boolean;
}) {
  if (!evidence || !view.log_evidence) {
    return <span className="text-muted">{logs ? '-' : 'not logged'}</span>;
  }
  const title = [evidenceText(evidence, view.log_evidence), ...evidence.flows.map(flowText)].join('\n');
  return (
    <span title={title}>
      <Badge size="sm" tone={evidenceTone(evidence)}>
        {passBlockText(evidence.passes, evidence.blocks) || 'none'}
      </Badge>
    </span>
  );
}

/** The log evidence of labels no rule of the backup has: automatic rules (default deny, bogons...) or rules removed since. */
function UnmatchedEvidence({ view }: { view: OpnsenseRulesView }) {
  const info = view.log_evidence;
  if (!info || info.unmatched.length === 0) return null;
  return (
    <div>
      <h4 style={{ margin: 'var(--space-3) 0 var(--space-2)', fontSize: 'var(--text-base)' }}>
        Logged by automatic or unknown rules ({info.window_hours} h)
      </h4>
      <div style={SCROLL_X_STYLE}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Rule</th>
              <th>Label</th>
              <th>Log</th>
              <th>Recent flows</th>
            </tr>
          </thead>
          <tbody>
            {info.unmatched.map((entry) => (
              <tr key={entry.rule_key}>
                <td>{entry.name}</td>
                <td>
                  <code style={{ fontSize: '0.72rem' }}>{entry.rule_key}</code>
                </td>
                <td title={evidenceText(entry, info)}>
                  <Badge size="sm" tone={evidenceTone(entry)}>
                    {passBlockText(entry.passes, entry.blocks) || 'none'}
                  </Badge>
                  {entry.seen_on.length > 0 && <div className="text-muted">{entry.seen_on.join(', ')}</div>}
                </td>
                <td>
                  {entry.flows.length ? (
                    entry.flows.map((flow) => <div key={flowText(flow)}>{flowText(flow)}</div>)
                  ) : (
                    <span className="text-muted">-</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function interfaceLabel(view: OpnsenseRulesView, key: string): string {
  const found = view.interfaces.find((i) => i.key === key);
  if (!found) return key;
  return found.description ? `${found.description} (${key}, ${found.device})` : `${key} (${found.device})`;
}

function RulesDiff({ hostId, newest }: { hostId: number; newest: number | null }) {
  const ids = useId();
  const backups = useHostConfigBackups(hostId, 30, true, 'success');
  const list = backups.data ?? [];
  const [to, setTo] = useState<number | null>(null);
  const [from, setFrom] = useState<number | null>(null);
  const toId = to ?? newest ?? list[0]?.id ?? null;
  const fromId = from ?? list.find((b) => b.id !== toId)?.id ?? null;
  const diff = useOpnsenseRulesDiff(hostId, fromId, toId);

  if (backups.isPending) return <LoadingState />;
  if (list.length < 2) {
    return <EmptyState compact message="Only one backup of this firewall" description="A diff needs two backups." />;
  }

  const options = list.map((b) => (
    <option key={b.id} value={b.id}>
      #{b.id} · {formatBackendDateTime(b.captured_at, '-')}
    </option>
  ));

  return (
    <div className="stack stack-sm">
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-3)' }}>
        <div className="form-group" style={{ margin: 0 }}>
          <label htmlFor={`${ids}-from`}>From backup</label>
          <select
            id={`${ids}-from`}
            className="form-select"
            value={fromId ?? ''}
            onChange={(e) => setFrom(Number(e.target.value))}
          >
            {options}
          </select>
        </div>
        <div className="form-group" style={{ margin: 0 }}>
          <label htmlFor={`${ids}-to`}>To backup</label>
          <select id={`${ids}-to`} className="form-select" value={toId ?? ''} onChange={(e) => setTo(Number(e.target.value))}>
            {options}
          </select>
        </div>
      </div>
      {fromId === toId ? (
        <EmptyState compact message="Pick two different backups" />
      ) : diff.isPending ? (
        <LoadingState />
      ) : diff.error ? (
        <EmptyState compact message="Could not compare the backups" description={(diff.error as Error).message} />
      ) : !diff.data.available ? (
        <EmptyState compact message="Nothing to compare" description={diff.data.message} />
      ) : diff.data.summary.rules + diff.data.summary.aliases + diff.data.summary.nat === 0 ? (
        <EmptyState compact message="No rule, alias or NAT change between these backups" />
      ) : (
        <div className="stack stack-sm" style={{ fontSize: '0.82rem' }}>
          <DiffSection
            title="Rules added"
            rows={diff.data.rules.added.map((r) => `#${r.number} ${r.action} ${endpointText(r.source)} → ${endpointText(r.destination)} ${r.description}`)}
            tone="success"
          />
          <DiffSection
            title="Rules removed"
            rows={diff.data.rules.removed.map((r) => `#${r.number} ${r.action} ${endpointText(r.source)} → ${endpointText(r.destination)} ${r.description}`)}
            tone="danger"
          />
          <DiffSection
            title="Rules changed"
            rows={diff.data.rules.changed.map(
              (c) =>
                `#${c.number_before} → #${c.number_after} ${c.after.description}: ` +
                (c.changes.length
                  ? c.changes.map((f) => `${f.field} ${changeText(f.before)} → ${changeText(f.after)}`).join('; ')
                  : 'moved'),
            )}
            tone="warning"
          />
          <DiffSection
            title="Aliases"
            rows={[
              ...diff.data.aliases.added.map((a) => `added ${a.name} (${a.type})`),
              ...diff.data.aliases.removed.map((a) => `removed ${a.name} (${a.type})`),
              ...diff.data.aliases.changed.map(
                (a) => `${a.name}: ${a.changes.map((f) => `${f.field} ${changeText(f.before)} → ${changeText(f.after)}`).join('; ')}`,
              ),
            ]}
            tone="info"
          />
          <DiffSection
            title="NAT"
            rows={[
              ...(diff.data.nat.outbound_mode
                ? [`outbound mode ${diff.data.nat.outbound_mode.before} → ${diff.data.nat.outbound_mode.after}`]
                : []),
              ...(['port_forwards', 'outbound', 'one_to_one'] as const).flatMap((part) => [
                ...diff.data.nat[part].added.map((i) => `${part.replace('_', ' ')} added: ${changeText(i.after.description) || i.key}`),
                ...diff.data.nat[part].removed.map((i) => `${part.replace('_', ' ')} removed: ${changeText(i.before.description) || i.key}`),
                ...diff.data.nat[part].changed.map(
                  (i) => `${part.replace('_', ' ')} changed: ${i.changes.map((f) => `${f.field} ${changeText(f.before)} → ${changeText(f.after)}`).join('; ')}`,
                ),
              ]),
            ]}
            tone="info"
          />
        </div>
      )}
    </div>
  );
}

function DiffSection({ title, rows, tone }: { title: string; rows: string[]; tone: 'success' | 'danger' | 'warning' | 'info' }) {
  if (!rows.length) return null;
  return (
    <div>
      <h4 style={{ margin: '0 0 var(--space-1)', fontSize: 'var(--text-base)' }}>
        {title} <Badge size="sm" tone={tone}>{rows.length}</Badge>
      </h4>
      <ul style={{ margin: 0, paddingLeft: '1.2rem' }}>
        {rows.map((row, i) => (
          <li key={i}>{row}</li>
        ))}
      </ul>
    </div>
  );
}
