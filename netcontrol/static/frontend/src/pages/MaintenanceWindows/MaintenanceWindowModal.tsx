import { type FormEvent, useId, useState } from 'react';

import { groupLabel, type InventoryGroupFull } from '@/api/inventory';
import {
  type MaintenanceWindow,
  type MaintenanceWindowPayload,
  type WindowPolicy,
  type WindowRecurrence,
  WEEKDAYS,
  toggleWeekdayBit,
  useCreateMaintenanceWindow,
  useMaintenanceWindow,
  useUpdateMaintenanceWindow,
} from '@/api/maintenanceWindows';
import { Callout } from '@/components/Callout';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';
import { localInputToIso, toLocalInputValue } from '@/lib/datetime';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  editingId?: number | null;
  groups: InventoryGroupFull[];
}

const DEFAULT_PAYLOAD: MaintenanceWindowPayload = {
  name: '',
  description: '',
  start_at: '',
  end_at: '',
  recurrence: 'none',
  weekday_mask: 0,
  policy: 'block_outside_window',
  enabled: true,
  group_ids: [],
};

function payloadFromWindow(w: MaintenanceWindow): MaintenanceWindowPayload {
  return {
    name: w.name,
    description: w.description,
    start_at: w.start_at,
    end_at: w.end_at,
    recurrence: w.recurrence,
    weekday_mask: w.weekday_mask,
    policy: w.policy,
    enabled: !!w.enabled,
    group_ids: w.group_ids || [],
  };
}

export function MaintenanceWindowModal({ isOpen, onClose, editingId, groups }: Props) {
  const isEdit = editingId != null;
  const existing = useMaintenanceWindow(isOpen && isEdit ? editingId : null);
  const create = useCreateMaintenanceWindow();
  const update = useUpdateMaintenanceWindow();
  const formId = useId();

  const isPending = create.isPending || update.isPending;
  // The form mounts only once its window has loaded, so it never shows another
  // window's values or blanks, and Save stays off until there is something to save.
  const ready = !isEdit || !!existing.data;

  const handleSubmit = (payload: MaintenanceWindowPayload, onError: (message: string) => void) => {
    const opts = {
      onSuccess: () => onClose(),
      onError: (e: unknown) => onError((e as Error).message),
    };
    if (editingId != null) {
      update.mutate({ id: editingId, data: payload }, opts);
    } else {
      create.mutate(payload, opts);
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={isEdit ? 'Edit Maintenance Window' : 'New Maintenance Window'}
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button
            type="submit"
            form={formId}
            className="btn btn-primary"
            disabled={!ready || isPending}
          >
            {isPending ? 'Saving…' : isEdit ? 'Save' : 'Create'}
          </button>
        </>
      }
    >
      {ready ? (
        <WindowForm
          // Seeded once per window: a background refetch must not overwrite edits.
          key={editingId ?? 'new'}
          formId={formId}
          initial={existing.data ? payloadFromWindow(existing.data) : DEFAULT_PAYLOAD}
          groups={groups}
          onSubmit={handleSubmit}
        />
      ) : existing.isError ? (
        <QueryError what="maintenance window" query={existing} />
      ) : (
        <LoadingState />
      )}
    </Modal>
  );
}

interface WindowFormProps {
  formId: string;
  initial: MaintenanceWindowPayload;
  groups: InventoryGroupFull[];
  onSubmit: (payload: MaintenanceWindowPayload, onError: (message: string) => void) => void;
}

function WindowForm({ formId, initial, groups, onSubmit }: WindowFormProps) {
  const fid = useId();
  const [form, setForm] = useState<MaintenanceWindowPayload>(initial);
  const [startLocal, setStartLocal] = useState(() => toLocalInputValue(initial.start_at));
  const [endLocal, setEndLocal] = useState(() => toLocalInputValue(initial.end_at));
  const [error, setError] = useState('');

  const toggleGroup = (id: number) => {
    setForm((f) => {
      const has = f.group_ids.includes(id);
      return {
        ...f,
        group_ids: has ? f.group_ids.filter((g) => g !== id) : [...f.group_ids, id],
      };
    });
  };

  const handleSave = (e: FormEvent) => {
    e.preventDefault();
    setError('');
    const startIso = localInputToIso(startLocal);
    const endIso = localInputToIso(endLocal);
    if (!form.name.trim()) {
      setError('Name is required');
      return;
    }
    if (!startIso || !endIso) {
      setError('Start and end times are required');
      return;
    }
    if (form.recurrence === 'none' && new Date(endIso) <= new Date(startIso)) {
      setError('End time must be after start time');
      return;
    }
    if (form.recurrence === 'weekly' && form.weekday_mask === 0) {
      setError('Pick at least one weekday for weekly recurrence');
      return;
    }
    onSubmit(
      {
        ...form,
        name: form.name.trim(),
        start_at: startIso,
        end_at: endIso,
        // For non-weekly recurrence we don't care what the mask is; clear
        // it so the stored value stays meaningful.
        weekday_mask: form.recurrence === 'weekly' ? form.weekday_mask : 0,
      },
      setError,
    );
  };

  const half = { flex: '1 1 200px' };

  return (
    <form id={formId} onSubmit={handleSave} noValidate>
      <div className="form-group">
        <label className="form-label" htmlFor={`${fid}-name`}>Name</label>
        <input
          id={`${fid}-name`}
          type="text"
          className="form-input"
          value={form.name}
          onChange={(e) => setForm({ ...form, name: e.target.value })}
          placeholder="Weekly prod patching"
        />
      </div>

      <div className="form-group">
        <label className="form-label" htmlFor={`${fid}-description`}>Description</label>
        <textarea
          id={`${fid}-description`}
          className="form-textarea"
          rows={2}
          value={form.description || ''}
          onChange={(e) => setForm({ ...form, description: e.target.value })}
        />
      </div>

      <div className="form-row">
        <div className="form-group" style={half}>
          <label className="form-label" htmlFor={`${fid}-start`}>Start</label>
          <input
            id={`${fid}-start`}
            type="datetime-local"
            className="form-input"
            value={startLocal}
            onChange={(e) => setStartLocal(e.target.value)}
          />
        </div>
        <div className="form-group" style={half}>
          <label className="form-label" htmlFor={`${fid}-end`}>End</label>
          <input
            id={`${fid}-end`}
            type="datetime-local"
            className="form-input"
            value={endLocal}
            onChange={(e) => setEndLocal(e.target.value)}
          />
        </div>
      </div>

      <div className="form-row">
        <div className="form-group" style={half}>
          <label className="form-label" htmlFor={`${fid}-recurrence`}>Recurrence</label>
          <select
            id={`${fid}-recurrence`}
            className="form-select"
            value={form.recurrence}
            onChange={(e) =>
              setForm({ ...form, recurrence: e.target.value as WindowRecurrence })
            }
          >
            <option value="none">One-shot</option>
            <option value="daily">Daily</option>
            <option value="weekly">Weekly</option>
          </select>
        </div>
        <div className="form-group" style={half}>
          <label className="form-label" htmlFor={`${fid}-policy`}>Policy</label>
          <select
            id={`${fid}-policy`}
            className="form-select"
            value={form.policy}
            onChange={(e) => setForm({ ...form, policy: e.target.value as WindowPolicy })}
          >
            <option value="block_outside_window">Block changes outside window</option>
            <option value="warn_outside_window">Warn outside window</option>
            <option value="allow_changes">Allow inside window only (advisory)</option>
          </select>
        </div>
      </div>

      {form.recurrence === 'weekly' && (
        <div className="form-group">
          <div className="form-label" id={`${fid}-weekdays`}>Weekdays</div>
          <div
            role="group"
            aria-labelledby={`${fid}-weekdays`}
            style={{ display: 'flex', gap: 'var(--space-1)', flexWrap: 'wrap' }}
          >
            {WEEKDAYS.map((d) => {
              const on = !!(form.weekday_mask & d.bit);
              return (
                <button
                  key={d.bit}
                  type="button"
                  className={`btn btn-sm ${on ? 'btn-primary' : 'btn-ghost'}`}
                  aria-pressed={on}
                  onClick={() =>
                    setForm({ ...form, weekday_mask: toggleWeekdayBit(form.weekday_mask, d.bit) })
                  }
                >
                  {d.short}
                </button>
              );
            })}
          </div>
        </div>
      )}

      <div className="form-group">
        <div className="form-label" id={`${fid}-scope`}>Scope</div>
        <div
          role="group"
          aria-labelledby={`${fid}-scope`}
          aria-describedby={`${fid}-scope-help`}
          style={{
            display: 'flex',
            gap: 'var(--space-1)',
            flexWrap: 'wrap',
            maxHeight: 140,
            overflowY: 'auto',
          }}
        >
          {groups.length === 0 && (
            <span style={{ color: 'var(--text-muted)' }}>No inventory groups defined.</span>
          )}
          {groups.map((g) => {
            const on = form.group_ids.includes(g.id);
            return (
              <button
                key={g.id}
                type="button"
                className={`btn btn-sm ${on ? 'btn-primary' : 'btn-ghost'}`}
                aria-pressed={on}
                onClick={() => toggleGroup(g.id)}
              >
                {groupLabel(g)}
              </button>
            );
          })}
        </div>
        <div className="form-help" id={`${fid}-scope-help`}>
          Pick the inventory groups this window applies to. Leave empty to apply globally.
        </div>
      </div>

      <label className="form-check">
        <input
          type="checkbox"
          checked={form.enabled}
          onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
        />
        <span>Enabled</span>
      </label>

      {error && <Callout tone="danger">{error}</Callout>}
    </form>
  );
}
