import { useEffect, useMemo, useRef, useState } from 'react';

import { usePathTrace, type PathDirection, type PathTrace as PathTraceResult, type PathTraceQuery } from '@/api/meraki';

import { hopTitle, itemWhere, stageLabel, statusMark, traceEnds, traceHighlight, verdictLabel, type TraceHighlight } from './pathTrace';

const MUTED = 'var(--text-muted, #868e96)';
const WARNING = 'var(--warning, #f59f00)';

type TraceQuery = ReturnType<typeof usePathTrace>;

/** One word for where the other direction's trace stands. */
function verdictWord(trace: TraceQuery): string {
  if (trace.isPending) return 'tracing…';
  if (trace.error) return 'trace failed.';
  if (!trace.data?.applies) return 'no trace.';
  return `${verdictLabel(trace.data.verdict).label}.`;
}

function Direction({ title, direction }: { title: string; direction: PathDirection | undefined }) {
  if (!direction) return null;
  const verdict = verdictLabel(direction.verdict);
  return (
    <div style={{ margin: '0.3rem 0 0 0' }}>
      <div>
        <strong>{title}</strong>: <span style={{ color: verdict.color }}>{verdict.label}</span>
        {direction.summary ? <span className="text-muted"> · {direction.summary}</span> : null}
      </div>
      {direction.hops.length > 0 && (
        <ol style={{ listStyle: 'none', margin: '0.15rem 0 0 0', padding: 0 }}>
          {direction.hops.map((hop, index) => {
            const hopMark = statusMark(hop.status);
            return (
              <li key={`${index}|${hop.node ?? 'internet'}`} style={{ marginTop: '0.2rem' }}>
                <div style={{ display: 'flex', gap: '0.4rem' }}>
                  <span aria-label={hop.status} style={{ color: hopMark.color, minWidth: '1em', textAlign: 'center' }}>
                    {hopMark.mark}
                  </span>
                  <span style={{ fontWeight: 600 }}>{hopTitle(hop, index)}</span>
                </div>
                {hop.items.map((item, itemIndex) => {
                  const mark = statusMark(item.status);
                  return (
                    <div key={itemIndex} style={{ display: 'flex', gap: '0.4rem', marginLeft: '1.4rem' }}>
                      <span aria-label={item.status} style={{ color: mark.color, minWidth: '1em', textAlign: 'center' }}>
                        {mark.mark}
                      </span>
                      <span>
                        <span className="text-muted">{stageLabel(item.stage)} · </span>
                        <strong>{itemWhere(item)}:</strong> {item.text}
                      </span>
                    </div>
                  );
                })}
              </li>
            );
          })}
        </ol>
      )}
    </div>
  );
}

function Result({ result, query }: { result: PathTraceResult; query: PathTraceQuery }) {
  const asymmetric = result.asymmetric;
  const source = result.source?.address || query.source;
  const destination = result.destination?.address || query.destination;
  return (
    <>
      {asymmetric && (
        <div style={{ color: asymmetric.status === 'yes' ? WARNING : MUTED }}>
          <strong>Asymmetric routing</strong>: {asymmetric.status === 'yes' ? 'yes' : asymmetric.status === 'no' ? 'no' : 'unknown'}
          {asymmetric.text ? `. ${asymmetric.text}` : '.'}
        </div>
      )}
      <Direction title={`Request, ${source} → ${destination}`} direction={result.request} />
      <Direction title={`Replies, ${destination} → ${source}`} direction={result.reply} />
      {(result.notes ?? []).map((note) => (
        <div key={note} className="text-muted">ⓘ {note}</div>
      ))}
    </>
  );
}

/**
 * The flow of one Path Mode leg traced hop by hop by the server: at every
 * device the policies, ACLs, security groups, NAT rules and routes it hits,
 * for the request and the replies, whether routing is asymmetric, and the
 * same traffic the other way round as a new connection (Reverse).
 */
export function PathTrace({
  forward,
  backward,
  onHighlight,
}: {
  forward: PathTraceQuery;
  backward: PathTraceQuery;
  /** Called with the request hops of the direction shown, null when there are none. */
  onHighlight?: (highlight: TraceHighlight | null) => void;
}) {
  const [reversed, setReversed] = useState(false);
  const forwardTrace = usePathTrace(forward);
  const backwardTrace = usePathTrace(backward);
  const shown = reversed ? backwardTrace : forwardTrace;
  const other = reversed ? forwardTrace : backwardTrace;
  const shownQuery = reversed ? backward : forward;
  const otherQuery = reversed ? forward : backward;

  const data = shown.data;
  const highlight = useMemo(() => (data?.applies ? traceHighlight(data.request) : null), [data]);
  const onHighlightRef = useRef(onHighlight);
  useEffect(() => {
    onHighlightRef.current = onHighlight;
  });
  useEffect(() => {
    onHighlightRef.current?.(highlight);
  }, [highlight]);
  useEffect(() => () => onHighlightRef.current?.(null), []);

  const reverseButton = (
    <button
      type="button"
      className="btn btn-sm btn-secondary"
      aria-pressed={reversed}
      onClick={() => setReversed((r) => !r)}
      style={{ marginLeft: '0.4rem' }}
    >
      {reversed ? `Reverse: back to ${traceEnds(otherQuery)}` : `Reverse: trace ${traceEnds(otherQuery)} as a new connection`}
    </button>
  );

  let head;
  if (shown.isPending) {
    head = <span className="text-muted">Tracing {traceEnds(shownQuery)}…</span>;
  } else if (shown.error) {
    head = <span style={{ color: 'var(--danger)' }}>Trace of {traceEnds(shownQuery)} failed: {(shown.error as Error).message}</span>;
  } else if (!data?.applies) {
    head = <span className="text-muted">ⓘ No trace: {data?.summary ?? 'the server returned nothing.'}</span>;
  } else {
    const verdict = verdictLabel(data.verdict);
    head = (
      <span>
        <strong style={{ color: verdict.color }}>{verdict.label}</strong>
        {data.traffic ? <span className="text-muted"> ({data.traffic})</span> : null}: {data.summary}
      </span>
    );
  }

  return (
    <div style={{ margin: '0.2rem 0 0.35rem 0' }}>
      <div>
        {head}
        {reverseButton}
      </div>
      <div className="text-muted">
        {reversed ? `Original direction (${traceEnds(otherQuery)})` : `Reverse direction (${traceEnds(otherQuery)}, new connection)`}:{' '}
        {verdictWord(other)}
      </div>
      {data?.applies && <Result result={data} query={shownQuery} />}
    </div>
  );
}
