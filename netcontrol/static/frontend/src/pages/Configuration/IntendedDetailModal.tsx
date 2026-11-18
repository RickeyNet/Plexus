import { useState } from 'react';

import { CustomDataError } from '@/api/customData';
import { type IntendedExtraLine, type IntendedLine, useGenerateIntended, useIntendedHost } from '@/api/intendedConfig';
import { StatusBadge } from '@/components/Badge';
import { BusyButton } from '@/components/BusyButton';
import { Callout } from '@/components/Callout';
import { CopyButton } from '@/components/CopyButton';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';
import { formatBackendDateTime } from '@/lib/datetime';
import { useCanWriteGroup } from '@/lib/objectScope';

import { extraParentText, generateSummary } from './intendedHelpers';
import { RemediationSection } from './IntendedRemediation';
import { writeControl } from './scopeGating';

/**
 * The intended text, one line per row. A line the device's backup lacks is
 * marked with "-" and read out as "Missing", not only coloured.
 */
export function IntendedText({ lines }: { lines: IntendedLine[] }) {
  return (
    <pre className="drift-diff-viewer" aria-label="Intended configuration">
      {lines.map((l, i) =>
        l.missing ? (
          <span key={i} className="diff-removed">
            <span aria-hidden="true">- </span>
            <span className="sr-only">Missing: </span>
            {l.text}
            {'\n'}
          </span>
        ) : (
          <span key={i}>
            {'  '}
            {l.text}
            {'\n'}
          </span>
        ),
      )}
    </pre>
  );
}

/** Backup lines the intended configuration lacks, each under its parent lines. */
export function ExtraLines({ extra }: { extra: IntendedExtraLine[] }) {
  if (extra.length === 0) return <EmptyState compact message="No extra lines on the device." />;
  return (
    <ul className="drift-diff-viewer" style={{ listStyle: 'none', margin: 0 }} aria-label="Extra on device">
      {extra.map((x, i) => (
        <li key={i}>
          <span className="text-muted">{extraParentText(x.path)}</span>
          <div style={{ paddingLeft: 'var(--space-4)' }}>{x.text.trim()}</div>
        </li>
      ))}
    </ul>
  );
}

/** A host's intended configuration: the text with missing lines marked, the extra lines, the remediation commands, Copy and Regenerate. */
export function IntendedDetailModal({ hostId, onClose }: { hostId: number; onClose: () => void }) {
  const q = useIntendedHost(hostId);
  const generate = useGenerateIntended();
  const [notice, setNotice] = useState<{ tone: 'success' | 'danger'; text: string } | null>(null);
  const d = q.data;
  // Regenerating stores the host's intended configuration: a write.
  const canWrite = useCanWriteGroup(d?.group_id);

  const regenerate = async () => {
    setNotice(null);
    try {
      const res = await generate.mutateAsync({ host_ids: [hostId] });
      // The mutation invalidates the intended-config queries, which refetches this host's detail.
      setNotice({ tone: 'success', text: generateSummary(res) });
    } catch (err) {
      setNotice({ tone: 'danger', text: `The configuration was not regenerated: ${(err as Error).message}` });
    }
  };

  const notFound = q.error instanceof CustomDataError && q.error.status === 404;
  let body;
  if (q.isError && !d && notFound)
    body = (
      <EmptyState
        compact
        message="This host has no intended configuration."
        description="No enabled device template matches it any more."
      />
    );
  else if (q.isError && !d) body = <QueryError what="the intended configuration" query={q} />;
  else if (!d) body = <LoadingState text="Loading the intended configuration…" />;
  else
    body = (
      <div className="stack">
        <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap', alignItems: 'center' }}>
          <span>
            Template <strong>{d.template_name || '-'}</strong>
          </span>
          <StatusBadge status={d.status} size="sm" />
          <StatusBadge status={d.compliance} kind="compliance" size="sm" />
          <span className="text-muted" style={{ fontSize: 'var(--text-sm)' }}>
            Generated {formatBackendDateTime(d.generated_at)}
          </span>
        </div>
        <div className="text-muted" style={{ fontSize: 'var(--text-sm)' }}>
          {d.backup
            ? `Compared with the backup captured ${formatBackendDateTime(d.backup.captured_at)} (backup ${d.backup.id}).`
            : 'No backup to compare with.'}
        </div>
        {d.status === 'error' && (
          <Callout tone="danger" title="The template did not render">
            {d.error || 'No detail was given.'}
          </Callout>
        )}
        <section aria-label="Intended text">
          <div style={{ fontWeight: 600, marginBottom: 'var(--space-1)' }}>
            Intended configuration{d.missing_count ? ` (${d.missing_count.toLocaleString()} missing)` : ''}
          </div>
          {d.missing_count > 0 && (
            <div className="form-help" style={{ marginBottom: 'var(--space-1)' }}>
              Lines marked “-” are missing from the device&apos;s backup.
            </div>
          )}
          {d.lines.length ? <IntendedText lines={d.lines} /> : <EmptyState compact message="The intended configuration is empty." />}
        </section>
        <section aria-label="Extra on device">
          <div style={{ fontWeight: 600, marginBottom: 'var(--space-1)' }}>Extra on device ({d.extra.length.toLocaleString()})</div>
          <div className="form-help" style={{ marginBottom: 'var(--space-1)' }}>
            Backup lines inside a block the template writes that the template does not have. They do not change compliance.
          </div>
          <ExtraLines extra={d.extra} />
        </section>
        <RemediationSection hostId={hostId} groupId={d.group_id} />
      </div>
    );

  return (
    <Modal
      isOpen
      onClose={onClose}
      size="large"
      title={`Intended configuration: ${d?.hostname ?? `host ${hostId}`}`}
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
          <CopyButton className="btn btn-secondary" text={d?.config_text ?? ''} disabled={!d?.config_text} />
          <BusyButton
            className="btn btn-primary"
            busy={generate.isPending}
            busyLabel="Regenerating…"
            {...writeControl(canWrite)}
            onClick={() => void regenerate()}
          >
            Regenerate
          </BusyButton>
        </>
      }
    >
      {notice && (
        <Callout tone={notice.tone} role={notice.tone === 'success' ? 'status' : 'alert'}>
          {notice.text}
        </Callout>
      )}
      {body}
    </Modal>
  );
}
