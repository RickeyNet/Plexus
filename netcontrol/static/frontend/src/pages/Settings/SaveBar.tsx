import type { ReactNode } from 'react';

import { BusyButton } from '@/components/BusyButton';

import { FormStatus, StatusLine } from './StatusLine';
import { useReportUnsaved } from './unsaved-context';

interface SaveBarProps {
  /** Names the form in the unsaved-changes confirmation: "Login Rules". */
  name: string;
  /** True while the draft differs from the saved value. */
  dirty: boolean;
  busy: boolean;
  /** Button label; defaults to "Save". */
  label?: string;
  status?: FormStatus | null;
  /** Called by Discard; omit to hide the button. */
  onDiscard?: () => void;
  /**
   * Omit inside a <form> (the button submits it). Pass a handler when the
   * bar is not inside a form.
   */
  onSave?: () => void;
  /** Extra actions that are not part of saving ("Run Now"). */
  children?: ReactNode;
}

/**
 * The one footer for a Settings form that saves on demand: Save is enabled
 * only while there is something to save, an "Unsaved changes" marker shows
 * beside it, and the form is registered with the page's unsaved-changes
 * guard. Controls that apply immediately do not use this; they carry an
 * <AutoSaveNote> instead.
 */
export function SaveBar({
  name,
  dirty,
  busy,
  label = 'Save',
  status = null,
  onDiscard,
  onSave,
  children,
}: SaveBarProps) {
  useReportUnsaved(name, dirty);
  return (
    <div className="save-bar">
      <div className="save-bar-actions">
        <BusyButton
          type={onSave ? 'button' : 'submit'}
          className="btn btn-primary"
          busy={busy}
          busyLabel="Saving…"
          disabled={!dirty}
          title={dirty ? undefined : 'No changes to save'}
          onClick={onSave}
        >
          {label}
        </BusyButton>
        {onDiscard && dirty && (
          <button type="button" className="btn btn-ghost" onClick={onDiscard} disabled={busy}>
            Discard
          </button>
        )}
        {children}
        {dirty && (
          <span className="badge badge-warning" role="status">
            Unsaved changes
          </span>
        )}
      </div>
      <StatusLine status={status} />
    </div>
  );
}

/** Marks a control or section whose changes apply as soon as they are made. */
export function AutoSaveNote({ children = 'Changes here apply immediately.' }: { children?: ReactNode }) {
  return <p className="form-help autosave-note">{children}</p>;
}
