import { BusyButton } from '@/components/BusyButton';
import { DataTable } from '@/components/DataTable';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { usePatchBuiltinTrapRule, useTrapRules, type SyslogRule, type SyslogSeverity } from '@/api/syslogRules';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { INACTIVE_OPACITY } from './helpers';
import { autoResolveLabel, SYSLOG_SEVERITY_OPTIONS, thresholdLabel } from './syslogRules';

// Monitoring -> Configure -> Syslog Rules: the built-in SNMP trap rules
// (enable and severity only), listed under the syslog rules. Their alerts are
// their own family, metric trap_<key> (docs/snmp-traps.md).
export function TrapRulesSection() {
  const { alert } = useDialogs();
  const rules = useTrapRules();
  const patch = usePatchBuiltinTrapRule();
  const pending = usePendingKeys<string>();

  function change(rule: SyslogRule, data: { enabled?: boolean; severity?: SyslogSeverity }) {
    return pending.run(rule.key, async () => {
      try {
        await patch.mutateAsync({ key: rule.key, data });
      } catch (e) {
        void alert({ message: (e as Error).message, variant: 'error' });
      }
    });
  }

  return (
    <section style={{ marginTop: '1.5rem' }}>
      <h3 style={{ margin: '0 0 0.25rem 0' }}>SNMP trap rules</h3>
      <p className="text-muted" style={{ fontSize: '0.85em', marginTop: 0 }}>
        Built-in rules run on the server against traps from inventory hosts that carry the host&apos;s SNMP community.
        Their alerts have metric <code>trap_&lt;rule&gt;</code>, apart from the syslog and polled alerts.
      </p>
      {rules.error && !rules.data ? <QueryError what="trap rules" query={rules} /> : rules.isPending && <LoadingState />}
      {rules.data && (rules.data.length === 0 ? (
        <EmptyState message="No trap rules" />
      ) : (
        <DataTable aria-label="SNMP trap rules">
          <thead>
            <tr>
              <th>Rule</th>
              <th>Traps</th>
              <th>Severity</th>
              <th>Threshold</th>
              <th>Auto-resolve</th>
              <th aria-label="Actions" />
            </tr>
          </thead>
          <tbody>
            {rules.data.map((r) => {
              const busy = pending.isPending(r.key);
              return (
                <tr key={r.key}>
                  <td style={{ opacity: r.enabled ? 1 : INACTIVE_OPACITY }}>
                    <strong>{r.name}</strong>
                    <span className="text-muted" style={{ fontSize: '0.75em', marginLeft: '0.4rem' }}>built-in</span>
                    {!r.enabled && <span className="text-muted" style={{ fontSize: '0.75em', marginLeft: '0.3rem' }}>(disabled)</span>}
                    <div className="text-muted" style={{ fontSize: '0.8em' }}>{r.description}</div>
                    {r.families.length > 0 && (
                      <div className="text-muted" style={{ fontSize: '0.8em' }}>{r.families.join(', ')}</div>
                    )}
                  </td>
                  <td style={{ fontSize: '0.82em', maxWidth: '28rem', overflowWrap: 'anywhere' }}>
                    <code>{r.tags.join(', ')}</code>
                    {r.clear_tags.length > 0 && <div className="text-muted">Clears: <code>{r.clear_tags.join(', ')}</code></div>}
                  </td>
                  <td>
                    <label className="sr-only" htmlFor={`trap-sev-${r.key}`}>Severity of {r.name}</label>
                    <select
                      id={`trap-sev-${r.key}`}
                      className="form-select"
                      style={{ width: 'auto', minWidth: '7rem' }}
                      value={r.severity}
                      disabled={busy}
                      onChange={(e) => void change(r, { severity: e.target.value as SyslogSeverity })}
                    >
                      {SYSLOG_SEVERITY_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                    </select>
                  </td>
                  <td style={{ whiteSpace: 'nowrap' }}>{thresholdLabel(r)}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>{autoResolveLabel(r.auto_resolve_minutes)}</td>
                  <td>
                    <div style={{ display: 'flex', gap: '0.4rem', justifyContent: 'flex-end' }}>
                      <BusyButton className="btn btn-sm btn-secondary" busy={busy} onClick={() => void change(r, { enabled: !r.enabled })}>
                        {r.enabled ? 'Disable' : 'Enable'}
                      </BusyButton>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </DataTable>
      ))}
    </section>
  );
}
