import type { CSSProperties } from 'react';

import type { SyslogSeverity } from '@/api/syslogRules';

import { SYSLOG_SEVERITY_OPTIONS, type RuleSettingsForm } from './syslogRules';

// The fields every custom rule editor (syslog and SNMP trap rules) has: the
// name, the severity, and the threshold, auto-resolve and enabled settings.
// `onChange` takes the changed fields.

type Change = (patch: Partial<RuleSettingsForm>) => void;

export function RuleNameField({ formId, value, onChange }: { formId: string; value: string; onChange: Change }) {
  return (
    <div className="form-group">
      <label className="form-label" htmlFor={`${formId}-name`}>Name</label>
      <input id={`${formId}-name`} className="form-input" value={value} onChange={(e) => onChange({ name: e.target.value })} required maxLength={100} />
    </div>
  );
}

export function RuleSeverityField({ formId, value, onChange, style }: {
  formId: string;
  value: SyslogSeverity;
  onChange: Change;
  style?: CSSProperties;
}) {
  return (
    <div className="form-group" style={style}>
      <label className="form-label" htmlFor={`${formId}-severity`}>Severity</label>
      <select id={`${formId}-severity`} className="form-select" value={value} onChange={(e) => onChange({ severity: e.target.value as SyslogSeverity })}>
        {SYSLOG_SEVERITY_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
    </div>
  );
}

export function RuleThresholdFields({ formId, form, onChange }: { formId: string; form: RuleSettingsForm; onChange: Change }) {
  return (
    <>
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
        <div className="form-group" style={{ flex: '1 1 8rem' }}>
          <label className="form-label" htmlFor={`${formId}-count`}>Matches to raise</label>
          <input id={`${formId}-count`} className="form-input" type="number" min="1" max="1000" value={form.threshold_count} onChange={(e) => onChange({ threshold_count: e.target.value })} />
        </div>
        <div className="form-group" style={{ flex: '1 1 8rem' }}>
          <label className="form-label" htmlFor={`${formId}-window`}>Within (seconds)</label>
          <input id={`${formId}-window`} className="form-input" type="number" min="1" max="86400" value={form.threshold_window_seconds} onChange={(e) => onChange({ threshold_window_seconds: e.target.value })} />
        </div>
        <div className="form-group" style={{ flex: '1 1 8rem' }}>
          <label className="form-label" htmlFor={`${formId}-resolve`}>Auto-resolve (min, 0 = off)</label>
          <input id={`${formId}-resolve`} className="form-input" type="number" min="0" max="10080" value={form.auto_resolve_minutes} onChange={(e) => onChange({ auto_resolve_minutes: e.target.value })} />
        </div>
      </div>
      <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.9em' }}>
        <input type="checkbox" checked={form.enabled} onChange={(e) => onChange({ enabled: e.target.checked })} />
        Enabled
      </label>
    </>
  );
}
