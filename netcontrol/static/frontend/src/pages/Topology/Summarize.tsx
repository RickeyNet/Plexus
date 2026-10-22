import { useMemo, useState } from 'react';

import { useMerakiSubnets, useSummarize, useTopologySources, type SummarizeReport } from '@/api/meraki';
import { PageHelp } from '@/components/PageHelp';

import { DETAIL_CELL_STYLE, FIELD_STYLE, HEAD_STYLE, NOTE_STYLE, SCROLL_X_STYLE, TEXT_CELL_STYLE } from './helpers';
import {
  addressCount,
  buildSummarizeRequest,
  emptySummarizeForm,
  notMerakiForm,
  overlapText,
  routeSize,
  summaryHeading,
  type SummarizeForm,
} from './summarizeHelpers';
import { sweepProviders, sweepSources } from './sweep';
import { FilterFields } from './SweepFilterFields';

/**
 * The Summarize view of the Topology page: the fewest routes that cover a
 * typed list of addresses (rolled up to a prefix, capped at a number of
 * routes), each checked against the collected networks the filters keep, so
 * an aggregate that would also catch another source's network shows before
 * it is created.
 */
export function Summarize() {
  const [form, setForm] = useState<SummarizeForm>(emptySummarizeForm);
  const [formError, setFormError] = useState<string | null>(null);
  const subnetsQuery = useMerakiSubnets(true);
  const sourcesQuery = useTopologySources();
  const summarize = useSummarize();

  const subnets = useMemo(() => subnetsQuery.data?.subnets ?? [], [subnetsQuery.data]);
  const sources = useMemo(() => sweepSources(sourcesQuery.data?.sources ?? [], subnets), [sourcesQuery.data, subnets]);
  const providers = useMemo(() => sweepProviders(subnets), [subnets]);

  function update(patch: Partial<SummarizeForm>) {
    setForm((f) => ({ ...f, ...patch }));
  }

  function run() {
    const built = buildSummarizeRequest(form);
    if ('error' in built) {
      setFormError(built.error);
      return;
    }
    setFormError(null);
    summarize.mutate(built.request);
  }

  return (
    <div>
      <PageHelp
        pageKey="topology.summarize"
        title="Summarize addresses"
        text="Find the fewest routes that cover a list of IP addresses, for example the Meraki hosts an Azure route table must reach, and check each route against the networks collected from every source. Roll up to / widens each address to that prefix first (a /24 per address, say); At most N routes then merges the neighbouring routes that add the fewest addresses until no more than N of each IP version are left. Each route lists the collected networks it overlaps: inside the route, equal to it, or containing it. Untick Meraki (or press Not Meraki) to see only the routes that would also catch another source's network. Copy the routes from the box above the table."
      />

      <div className="card" style={{ padding: '0.75rem', marginBottom: '0.75rem' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', alignItems: 'flex-end' }}>
          <label style={{ ...FIELD_STYLE, flex: '1 1 320px' }}>
            <span className="form-label">Addresses</span>
            <textarea
              className="form-input"
              rows={6}
              placeholder="One IP address or network per line, or comma-separated"
              value={form.addresses}
              onChange={(e) => update({ addresses: e.target.value })}
              spellCheck={false}
              style={{ fontFamily: 'monospace', resize: 'vertical' }}
            />
          </label>
          <label style={{ ...FIELD_STYLE, minWidth: 110 }}>
            <span className="form-label">Roll up to /</span>
            <input
              className="form-input"
              type="number"
              min={0}
              max={128}
              placeholder="exact"
              value={form.prefix}
              onChange={(e) => update({ prefix: e.target.value })}
              title="Widen each address to this prefix length first; empty: exact"
            />
          </label>
          <label style={{ ...FIELD_STYLE, minWidth: 130 }}>
            <span className="form-label">At most N routes</span>
            <input
              className="form-input"
              type="number"
              min={1}
              placeholder="no limit"
              value={form.maxRoutes}
              onChange={(e) => update({ maxRoutes: e.target.value })}
              title="Merge neighbouring routes until no more than this many of each IP version are left; empty: no limit"
            />
          </label>
          <button type="button" className="btn btn-sm btn-primary" onClick={run} disabled={summarize.isPending}>
            {summarize.isPending ? 'Summarizing…' : 'Summarize'}
          </button>
          <button
            type="button"
            className="btn btn-sm btn-secondary"
            onClick={() => setForm((f) => notMerakiForm(f, providers))}
            title="Check against every provider but Meraki, every kind of network"
          >
            Not Meraki
          </button>
          <button
            type="button"
            className="btn btn-sm btn-secondary"
            onClick={() => { setForm(emptySummarizeForm()); setFormError(null); }}
          >
            Reset
          </button>
        </div>

        <FilterFields
          title="Check overlaps against"
          idPrefix="summarize-against"
          filters={form}
          onChange={update}
          sources={sources}
          providers={providers}
          note="The collected networks each route is checked against; untick Meraki to find overlaps with other sources."
        />
        {formError && <div style={{ color: 'var(--danger)', marginTop: '0.5rem' }}>{formError}</div>}
      </div>

      {summarize.error && (
        <div className="card" style={{ padding: '0.6rem 0.85rem', borderLeft: '3px solid var(--danger)' }}>
          Summary failed: {summarize.error.message.replace(/^\d{3} /, '')}
        </div>
      )}
      {summarize.data && <Results report={summarize.data} />}
    </div>
  );
}

function Results({ report }: { report: SummarizeReport }) {
  const [copied, setCopied] = useState(false);
  const overlapping = report.routes.filter((r) => r.overlaps.length).length;

  function copy() {
    void navigator.clipboard.writeText(report.text).then(() => {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    });
  }

  return (
    <div className="card" style={{ padding: '0.75rem' }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', alignItems: 'baseline' }}>
        <strong>{summaryHeading(report)}</strong>
        <span className="text-muted" style={NOTE_STYLE}>
          {overlapping ? `${overlapping} overlap a collected network` : 'None overlaps a collected network'}
        </span>
      </div>

      <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'flex-start', margin: '0.5rem 0 0.75rem' }}>
        <textarea
          className="form-input"
          readOnly
          rows={Math.min(10, Math.max(2, report.route_count))}
          value={report.text}
          aria-label="Routes"
          style={{ fontFamily: 'monospace', flex: '1 1 auto', maxWidth: 420, resize: 'vertical' }}
          onFocus={(e) => e.target.select()}
        />
        <button type="button" className="btn btn-sm btn-secondary" onClick={copy}>
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>

      <div style={SCROLL_X_STYLE}>
        <table className="data-table">
          <thead>
            <tr>
              <th style={HEAD_STYLE}>Route</th>
              <th style={HEAD_STYLE}>Covers</th>
              <th style={HEAD_STYLE}>Addresses</th>
              <th style={HEAD_STYLE}>Overlaps</th>
            </tr>
          </thead>
          <tbody>
            {report.routes.map((route) => (
              <tr key={route.cidr}>
                <td style={{ ...DETAIL_CELL_STYLE, whiteSpace: 'nowrap', fontFamily: 'monospace' }}>{route.cidr}</td>
                <td style={DETAIL_CELL_STYLE} title={route.inputs.join('\n')}>
                  {route.input_count === 1 ? '1 input' : `${route.input_count} inputs`}
                </td>
                <td style={{ ...DETAIL_CELL_STYLE, whiteSpace: 'nowrap' }}>
                  {routeSize(route)}
                  <span className="text-muted"> ({addressCount(route.input_addresses)} asked)</span>
                </td>
                <td style={TEXT_CELL_STYLE}>
                  {route.overlaps.length ? (
                    <>
                      <strong>{route.overlaps.length}</strong>
                      <ul style={{ margin: '0.2rem 0 0', paddingLeft: '1.1rem' }}>
                        {route.overlaps.map((o) => (
                          <li key={`${o.org_ref ?? ''}|${o.node_id}|${o.cidr}`}>{overlapText(o)}</li>
                        ))}
                      </ul>
                    </>
                  ) : (
                    <span style={{ color: 'var(--success)' }}>none</span>
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
