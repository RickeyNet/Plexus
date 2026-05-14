import { useEffect, useState } from 'react';

import { type InventoryGroupFull } from '@/api/inventory';
import {
  type MaintenanceWindowPayload,
  type WindowPolicy,
  type WindowRecurrence,
  WEEKDAYS,
  toggleWeekdayBit,
  useCreateMaintenanceWindow,
  useMaintenanceWindow,
  useUpdateMaintenanceWindow,
} from '@/api/maintenanceWindows';
import { Modal } from '@/components/Modal';

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

// HTML <input type="datetime-local"> uses "YYYY-MM-DDTHH:MM" (no zone,
// no seconds). We serialize the user's local time as UTC ISO when sending
// to the backend so the round-trip is unambiguous.
function localInputToIso(value: string): string {
  if (!value) return '';
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return '';
  return dt.toISOString();
}

function isoToLocalInput(iso: string): string {
  if (!iso) return '';
  const dt = new Date(iso);
  if (Number.isNaN(dt.getTime())) return '';
  const pad = (n: number) => String(n).padStart(2, '0');
  return (
    `${dt.getFullYear()}-${pad(dt.getMonth() + 1)}-${pad(dt.getDate())}` +
    `T${pad(dt.getHours())}:${pad(dt.getMinutes())}`
  );
}

export function MaintenanceWindowModal({ isOpen, onClose, editingId, groups }: Props) {
  const existing = useMaintenanceWindow(editingId ?? null);
  const create = useCreateMaintenanceWindow();
  const update = useUpdateMaintenanceWindow();

  const [form, setForm] = useState<MaintenanceWindowPayload>(DEFAULT_PAYLOAD);
  const [startLocal, setStartLocal] = useState('');
  const [endLocal, setEndLocal] = useState('');
  const [error, setError] = useState('');

  // Reset form when opening or when the existing window changes.
  useEffect(() => {
    if (!isOpen) return;
    if (editingId && existing.data) {
      setForm({
        name: existing.data.name,
        description: existing.data.description,
        start_at: existing.data.start_at,
        end_at: existing.data.end_at,
        recurrence: existing.data.recurrence,
        weekday_mask: existing.data.weekday_mask,
        policy: existing.data.policy,
        enabled: !!existing.data.enabled,
        group_ids: existing.data.group_ids || [],
      });
      setStartLocal(isoToLocalInput(existing.data.start_at));
      setEndLocal(isoToLocalInput(existing.data.end_at));
    } else if (!editingId) {
      setForm(DEFAULT_PAYLOAD);
      setStartLocal('');
      setEndLocal('');
    }
    setError('');
  }, [isOpen, editingId, existing.data]);

  const isEdit = editingId != null;
  const isPending = create.isPending || update.isPending;

  const toggleGroup = (id: number) => {
    setForm((f) => {
      const has = f.group_ids.includes(id);
      return {
        ...f,
        group_ids: has ? f.group_ids.filter((g) => g !== id) : [...f.group_ids, id],
      };
    });
  };

  const handleSave = () => {
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
    const payload: MaintenanceWindowPayload = {
      ...form,
      name: form.name.trim(),
      start_at: startIso,
      end_at: endIso,
      // For non-weekly recurrence we don't care what the mask is; clear
      // it so the stored value stays meaningful.
      weekday_mask: form.recurrence === 'weekly' ? form.weekday_mask : 0,
    };

    const opts = {
      onSuccess: () => onClose(),
      onError: (e: unknown) => setError((e as Error).message),
    };
    if (isEdit && editingId != null) {
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
      size="default"
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        <label>
          <div style={{ fontWeight: 600, fontSize: '0.85em' }}>Name</div>
          <input
            type="text"
            className="input"
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            style={{ width: '100%' }}
            placeholder="Weekly prod patching"
          />
        </label>

        <label>
          <div style={{ fontWeight: 600, fontSize: '0.85em' }}>Description</div>
          <textarea
            className="input"
            rows={2}
            value={form.description || ''}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
            style={{ width: '100%' }}
          />
        </label>

        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
          <label style={{ flex: 1, minWidth: 200 }}>
            <div style={{ fontWeight: 600, fontSize: '0.85em' }}>Start</div>
            <input
              type="datetime-local"
              className="input"
              value={startLocal}
              onChange={(e) => setStartLocal(e.target.value)}
              style={{ width: '100%' }}
            />
          </label>
          <label style={{ flex: 1, minWidth: 200 }}>
            <div style={{ fontWeight: 600, fontSize: '0.85em' }}>End</div>
            <input
              type="datetime-local"
              className="input"
              value={endLocal}
              onChange={(e) => setEndLocal(e.target.value)}
              style={{ width: '100%' }}
            />
          </label>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
          <label style={{ flex: 1, minWidth: 200 }}>
            <div style={{ fontWeight: 600, fontSize: '0.85em' }}>Recurrence</div>
            <select
              className="input"
              value={form.recurrence}
              onChange={(e) =>
                setForm({ ...form, recurrence: e.target.value as WindowRecurrence })
              }
              style={{ width: '100%' }}
            >
              <option value="none">One-shot</option>
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
            </select>
          </label>
          <label style={{ flex: 1, minWidth: 200 }}>
            <div style={{ fontWeight: 600, fontSize: '0.85em' }}>Policy</div>
            <select
              className="input"
              value={form.policy}
              onChange={(e) => setForm({ ...form, policy: e.target.value as WindowPolicy })}
              style={{ width: '100%' }}
            >
              <option value="block_outside_window">Block changes outside window</option>
              <option value="warn_outside_window">Warn outside window</option>
              <option value="allow_changes">Allow inside window only (advisory)</option>
            </select>
          </label>
        </div>

        {form.recurrence === 'weekly' && (
          <div>
            <div style={{ fontWeight: 600, fontSize: '0.85em', marginBottom: '0.25rem' }}>
              Weekdays
            </div>
            <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
              {WEEKDAYS.map((d) => {
                const on = !!(form.weekday_mask & d.bit);
                return (
                  <button
                    key={d.bit}
                    type="button"
                    className={`btn btn-sm ${on ? 'btn-primary' : 'btn-ghost'}`}
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

        <div>
          <div style={{ fontWeight: 600, fontSize: '0.85em', marginBottom: '0.25rem' }}>
            Scope
          </div>
          <p style={{ margin: '0 0 0.4rem', fontSize: '0.82em', color: 'var(--text-muted)' }}>
            Pick the inventory groups this window applies to. Leave empty to apply globally.
          </p>
          <div
            style={{
              display: 'flex',
              gap: '0.35rem',
              flexWrap: 'wrap',
              maxHeight: 140,
              overflowY: 'auto',
            }}
          >
            {groups.length === 0 && (
              <span style={{ color: 'var(--text-muted)', fontSize: '0.85em' }}>
                No inventory groups defined.
              </span>
            )}
            {groups.map((g) => {
              const on = form.group_ids.includes(g.id);
              return (
                <button
                  key={g.id}
                  type="button"
                  className={`btn btn-sm ${on ? 'btn-primary' : 'btn-ghost'}`}
                  onClick={() => toggleGroup(g.id)}
                >
                  {g.name}
                </button>
              );
            })}
          </div>
        </div>

        <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <input
            type="checkbox"
            checked={form.enabled}
            onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
          />
          <span>Enabled</span>
        </label>

        {error && (
          <div style={{ color: 'var(--danger)', fontSize: '0.85em' }}>{error}</div>
        )}

        <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button
            type="button"
            className="btn btn-primary"
            disabled={isPending}
            onClick={handleSave}
          >
            {isPending ? 'Saving…' : isEdit ? 'Save' : 'Create'}
          </button>
        </div>
      </div>
    </Modal>
  );
}
