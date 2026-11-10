import { type ReactNode, useState } from 'react';

import { Badge } from '@/components/Badge';
import { BusyButton } from '@/components/BusyButton';
import { Callout } from '@/components/Callout';
import { DeleteButton } from '@/components/DeleteButton';
import { useDialogs } from '@/components/DialogProvider-context';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { NumberField, FormRow } from './FormFields';
import type { FormStatus } from './StatusLine';
import { useReportUnsaved } from './unsaved-context';

/*
 * Pieces shared by the two delivery-target tabs (Notifications channels and
 * SIEM sinks): the per-row stats cells, Test/Edit/Delete actions, the test
 * outcome, the queue/retry/backoff fields and the editor modal.
 */

export interface TestResult {
  ok: boolean;
  error: string;
}

/** Runtime counters both dispatchers report per target. */
interface DeliveryStats {
  queue_depth: number;
  queue_size: number;
  delivered: number;
  dropped_queue_full: number;
  dropped_below_severity: number;
  last_error: string;
}

/** Queue, Delivered, Dropped and Last error cells for one table row. */
export function DeliveryStatsCells({ stats }: { stats: DeliveryStats | undefined }) {
  const lastError = stats?.last_error || '';
  return (
    <>
      <td>{stats ? `${stats.queue_depth}/${stats.queue_size}` : '-'}</td>
      <td>{stats?.delivered ?? 0}</td>
      <td>{(stats?.dropped_queue_full ?? 0) + (stats?.dropped_below_severity ?? 0)}</td>
      <td className="text-muted">
        {lastError ? (
          <span className="form-mono delivery-cell-truncate" title={lastError}>
            {lastError}
          </span>
        ) : (
          '-'
        )}
      </td>
    </>
  );
}

/** The latest Test outcome for a row, or "-" when it has not been tested. */
export function TestResultBadge({ result }: { result: TestResult | undefined }) {
  if (!result) return <span className="text-muted">-</span>;
  return result.ok ? (
    <Badge tone="success" size="sm">
      Passed
    </Badge>
  ) : (
    <Badge tone="danger" size="sm" title={result.error}>
      Failed
    </Badge>
  );
}

/** Right-aligned Test / Edit / Delete cell. */
export function RowActionsCell({
  name,
  testing,
  deleting,
  onTest,
  onEdit,
  onDelete,
}: {
  name: string;
  testing: boolean;
  deleting: boolean;
  onTest: () => void;
  onEdit: () => void;
  onDelete: () => void;
}) {
  return (
    <td>
      <div className="table-actions">
        <BusyButton
          className="btn btn-xs btn-secondary"
          busy={testing}
          busyLabel="Testing…"
          onClick={onTest}
          aria-label={`Test ${name}`}
        >
          Test
        </BusyButton>
        <button type="button" className="btn btn-xs btn-secondary" onClick={onEdit} aria-label={`Edit ${name}`}>
          Edit
        </button>
        <DeleteButton size="xs" onClick={onDelete} busy={deleting} aria-label={`Delete ${name}`} />
      </div>
    </td>
  );
}

/** The tab's latest action outcome (save, delete, test), shown above the table. */
export function NoticeCallout({ notice, onDismiss }: { notice: FormStatus | null; onDismiss: () => void }) {
  if (!notice) return null;
  return (
    <Callout
      tone={notice.kind === 'success' ? 'success' : 'danger'}
      action={
        <button type="button" className="btn btn-sm btn-ghost" onClick={onDismiss}>
          Dismiss
        </button>
      }
    >
      <span className="delivery-notice-text">{notice.message}</span>
    </Callout>
  );
}

export interface TargetTests {
  isPending: (id: string) => boolean;
  result: (id: string) => TestResult | undefined;
  test: (id: string, name: string) => Promise<void>;
}

/**
 * Per-row Test state for the table rendered by `children`: busy flags, the
 * last result per id, and an outcome reported through `onOutcome` so the
 * tab can show it above the table. A render-prop component (not an exported
 * hook) so this file exports components only.
 */
export function TargetTestsProvider({
  send,
  sentMessage,
  onOutcome,
  children,
}: {
  send: (id: string) => Promise<TestResult>;
  sentMessage: (name: string) => string;
  onOutcome: (status: FormStatus) => void;
  children: (tests: TargetTests) => ReactNode;
}) {
  const pending = usePendingKeys<string>();
  const [results, setResults] = useState<Record<string, TestResult>>({});

  const test = (id: string, name: string) =>
    pending.run(id, async () => {
      let res: TestResult;
      try {
        res = await send(id);
      } catch (err) {
        res = { ok: false, error: (err as Error).message };
      }
      setResults((prev) => ({ ...prev, [id]: res }));
      onOutcome(
        res.ok
          ? { kind: 'success', message: sentMessage(name) }
          : { kind: 'error', message: `Test failed for ${name}: ${res.error || 'no error detail returned.'}` },
      );
    });

  return <>{children({ isPending: pending.isPending, result: (id: string) => results[id], test })}</>;
}

interface RetrySettings {
  queue_size: number;
  max_retries: number;
  backoff_base: number;
  backoff_cap: number;
}

/**
 * The collapsible queue / retry / backoff fields. `noun` names what is
 * queued ("alert", "audit event"). Ranges match the backend's clamps.
 */
export function RetryFields({
  value,
  onChange,
  noun,
}: {
  value: RetrySettings;
  onChange: (key: keyof RetrySettings, v: number) => void;
  noun: string;
}) {
  return (
    <details>
      <summary style={{ cursor: 'pointer', marginBottom: 'var(--space-3)' }}>
        Advanced (queue, retry, backoff)
      </summary>
      <FormRow>
        <NumberField
          label="Queue size"
          flex="1 1 160px"
          min={10}
          max={100000}
          value={value.queue_size}
          onChange={(v) => onChange('queue_size', v)}
          help={`Pending ${noun}s held in memory. When full, the oldest is dropped.`}
        />
        <NumberField
          label="Max retries"
          flex="1 1 160px"
          min={0}
          max={20}
          value={value.max_retries}
          onChange={(v) => onChange('max_retries', v)}
          help={`Retries after a failed send before the ${noun} is given up. 0 sends once.`}
        />
        <NumberField
          label="Backoff base (s)"
          flex="1 1 160px"
          min={0.1}
          max={30}
          step="0.1"
          value={value.backoff_base}
          onChange={(v) => onChange('backoff_base', v)}
          help="Wait before the first retry; it doubles on each further retry."
        />
        <NumberField
          label="Backoff cap (s)"
          flex="1 1 160px"
          min={1}
          max={600}
          value={value.backoff_cap}
          onChange={(v) => onChange('backoff_cap', v)}
          help="Longest wait between retries."
        />
      </FormRow>
    </details>
  );
}

/**
 * The add/edit modal for a channel or sink: Save/Cancel in the footer, a
 * failed save shown inside the modal, and a confirm before closing over
 * unsaved edits.
 */
export function TargetEditorModal({
  title,
  formName,
  dirty,
  saving,
  primaryLabel,
  error,
  onSave,
  onClose,
  children,
}: {
  title: string;
  /** Names the form in unsaved-changes prompts: "Notification channel". */
  formName: string;
  dirty: boolean;
  saving: boolean;
  primaryLabel: string;
  error: string | null;
  onSave: () => void;
  onClose: () => void;
  children: ReactNode;
}) {
  const { confirm } = useDialogs();
  useReportUnsaved(formName, dirty);

  const requestClose = async () => {
    if (saving) return;
    if (
      dirty &&
      !(await confirm({
        title: 'Discard changes',
        message: `Discard your unsaved changes to this ${formName.toLowerCase()}?`,
        confirmLabel: 'Discard',
      }))
    )
      return;
    onClose();
  };

  return (
    <Modal
      isOpen
      onClose={() => void requestClose()}
      title={title}
      footer={
        <ModalActions
          onClose={() => void requestClose()}
          primaryLabel={primaryLabel}
          primaryBusy={saving}
          primaryBusyLabel="Saving…"
          onPrimary={onSave}
        />
      }
    >
      {error && <Callout tone="danger">{error}</Callout>}
      {children}
    </Modal>
  );
}
