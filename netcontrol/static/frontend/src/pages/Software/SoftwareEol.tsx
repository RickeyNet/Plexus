import { FormEvent, useId, useState } from 'react';

import { Badge } from '@/components/Badge';
import { Callout } from '@/components/Callout';
import { DataTable } from '@/components/DataTable';
import { DeleteButton } from '@/components/DeleteButton';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';
import { useDialogs } from '@/components/DialogProvider-context';
import { type SoftwarePlatformInfo, useSaveSoftwareSettings } from '@/api/software';
import {
  type SoftwareEolEntry,
  type SoftwareEolStatus,
  useDeleteSoftwareEolEntry,
  useSaveSoftwareEolEntry,
  useSoftwareEolEntries,
} from '@/api/softwareEol';
import { WARN_DAYS_MAX } from '@/lib/lifecycle';

import { type SoftwareEolEntryErrors, softwareEolChip, softwareEolTone, sourceLabel, validateSoftwareEolEntry } from './helpers';

/**
 * Software end of life per release series (not the hardware lifecycle of the
 * Lifecycle tab): the chip of a device's series status, and the card that
 * lists, adds, edits and deletes the end-of-life entries.
 */

export function SoftwareEolChip({ status }: { status: SoftwareEolStatus | null | undefined }) {
  const text = softwareEolChip(status);
  if (!status || !text) return null;
  return (
    <Badge size="sm" tone={softwareEolTone(status)} title={`${status.series}: ${status.basis}`}>
      {text}
    </Badge>
  );
}

interface CardProps {
  canWrite: boolean;
  isAdmin: boolean;
  platformLabel: (key: string) => string;
  platforms: SoftwarePlatformInfo[];
}

export function SoftwareEolCard({ canWrite, isAdmin, platformLabel, platforms }: CardProps) {
  const { alert, confirm } = useDialogs();
  const entries = useSoftwareEolEntries();
  const remove = useDeleteSoftwareEolEntry();
  const saveSettings = useSaveSoftwareSettings();
  const [editing, setEditing] = useState<SoftwareEolEntry | null | 'new'>(null);
  const [warnDays, setWarnDays] = useState<string | null>(null);

  const list = entries.data?.entries ?? [];
  const storedWarnDays = entries.data?.warn_days ?? 60;

  const handleDelete = async (entry: SoftwareEolEntry) => {
    const ok = await confirm({
      title: 'Delete end-of-life entry',
      message: `Delete the entry for ${platformLabel(entry.platform)} ${entry.series}? Its alerts resolve unless a built-in estimate still applies.`,
      confirmLabel: 'Delete',
      confirmVariant: 'danger',
    });
    if (!ok) return;
    try {
      await remove.mutateAsync(entry.id);
    } catch (err) {
      void alert({ message: (err as Error).message, variant: 'error' });
    }
  };

  const handleWarnDays = async () => {
    const days = Number(warnDays);
    if (!Number.isInteger(days) || days < 1 || days > WARN_DAYS_MAX) {
      void alert({ message: `The warning window is a whole number of days from 1 to ${WARN_DAYS_MAX}.`, variant: 'error' });
      return;
    }
    try {
      await saveSettings.mutateAsync({ eol_warn_days: days });
      await entries.refetch();
      setWarnDays(null);
    } catch (err) {
      void alert({ message: (err as Error).message, variant: 'error' });
    }
  };

  return (
    <div className="card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
        <h3 style={{ margin: 0 }}>Software End of Life</h3>
        {canWrite && (
          <button type="button" className="btn btn-primary btn-sm" onClick={() => setEditing('new')}>
            + Add Series
          </button>
        )}
      </div>
      <div className="text-muted" style={{ fontSize: '0.85em', marginBottom: '0.5rem' }}>
        The day each release series stops getting security fixes. OPNsense series are estimated from the release
        cadence (a series ends when its successor ships) and confirmed by the firewall's own major-upgrade report;
        an entry here overrides the estimate. A series counts as ending {storedWarnDays} days before its end of life.
      </div>
      {isAdmin && (
        <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center', marginBottom: '0.5rem' }}>
          <label htmlFor="software-eol-warn-days" style={{ fontSize: '0.88em' }}>
            Warning window (days)
          </label>
          <input
            id="software-eol-warn-days"
            className="form-input form-input-sm"
            style={{ width: 90 }}
            inputMode="numeric"
            value={warnDays ?? String(storedWarnDays)}
            onChange={(e) => setWarnDays(e.target.value)}
          />
          {warnDays != null && warnDays !== String(storedWarnDays) && (
            <button type="button" className="btn btn-secondary btn-sm" onClick={handleWarnDays} disabled={saveSettings.isPending}>
              {saveSettings.isPending ? 'Saving…' : 'Save Window'}
            </button>
          )}
        </div>
      )}
      {entries.isError && !entries.data ? (
        <QueryError what="end-of-life entries" query={entries} />
      ) : list.length === 0 ? (
        <p className="text-muted" style={{ margin: 0 }}>
          No entries. Add one per release series to give its devices an end-of-life status and alerts.
        </p>
      ) : (
        <DataTable>
          <thead>
            <tr>
              <th>Platform</th>
              <th>Series</th>
              <th>End of life</th>
              <th>Source</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {list.map((entry) => (
              <tr key={entry.id}>
                <td>{platformLabel(entry.platform)}</td>
                <td>
                  {entry.url ? (
                    <a href={entry.url} target="_blank" rel="noreferrer">
                      {entry.series}
                    </a>
                  ) : (
                    entry.series
                  )}
                  {!entry.enabled && (
                    <Badge size="sm" style={{ marginLeft: '0.4rem' }}>
                      disabled
                    </Badge>
                  )}
                  {entry.notes && (
                    <div className="text-muted" style={{ fontSize: '0.8em' }}>
                      {entry.notes}
                    </div>
                  )}
                </td>
                <td style={{ whiteSpace: 'nowrap' }}>{entry.eol_date}</td>
                <td>{sourceLabel(entry.source)}</td>
                <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                  {canWrite && (
                    <>
                      <button type="button" className="btn btn-secondary btn-sm" onClick={() => setEditing(entry)}>
                        Edit
                      </button>{' '}
                      <DeleteButton onClick={() => void handleDelete(entry)} />
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      )}
      {editing != null && (
        <SoftwareEolEntryModal
          entry={editing === 'new' ? null : editing}
          platforms={platforms}
          onClose={() => setEditing(null)}
        />
      )}
    </div>
  );
}

interface ModalProps {
  entry: SoftwareEolEntry | null;
  platforms: SoftwarePlatformInfo[];
  onClose: () => void;
}

export function SoftwareEolEntryModal({ entry, platforms, onClose }: ModalProps) {
  const save = useSaveSoftwareEolEntry();
  const formId = useId();
  const [platform, setPlatform] = useState(entry?.platform ?? '');
  const [series, setSeries] = useState(entry?.series ?? '');
  const [eolDate, setEolDate] = useState(entry?.eol_date ?? '');
  const [releaseDate, setReleaseDate] = useState(entry?.release_date ?? '');
  const [url, setUrl] = useState(entry?.url ?? '');
  const [notes, setNotes] = useState(entry?.notes ?? '');
  const [enabled, setEnabled] = useState(entry?.enabled ?? true);
  const [errors, setErrors] = useState<SoftwareEolEntryErrors>({});
  const [saveError, setSaveError] = useState<string | null>(null);

  const payload = () => ({
    platform,
    series: series.trim(),
    eol_date: eolDate.trim(),
    release_date: releaseDate.trim(),
    url: url.trim(),
    notes: notes.trim(),
    enabled,
  });
  const clear = (key: keyof SoftwareEolEntryErrors) => setErrors((prev) => ({ ...prev, [key]: undefined }));
  const blur = (key: keyof SoftwareEolEntryErrors) => {
    const found = validateSoftwareEolEntry(payload())[key];
    if (found) setErrors((prev) => ({ ...prev, [key]: found }));
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setSaveError(null);
    const body = payload();
    const found = validateSoftwareEolEntry(body);
    setErrors(found);
    if (Object.keys(found).length > 0) return;
    try {
      await save.mutateAsync({ id: entry?.id ?? null, payload: body });
      onClose();
    } catch (err) {
      setSaveError((err as Error).message);
    }
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={entry ? `Edit ${entry.series}` : 'Add Release Series'}
      size="medium"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={save.isPending}>
            {save.isPending ? 'Saving…' : entry ? 'Save Series' : 'Add Series'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={submit} noValidate>
        {saveError && <Callout tone="danger">{saveError}</Callout>}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 1rem' }}>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-platform`}>Platform</label>
            <select
              id={`${formId}-platform`}
              className="form-select"
              value={platform}
              onChange={(e) => {
                setPlatform(e.target.value);
                clear('platform');
              }}
              aria-invalid={!!errors.platform}
            >
              <option value="">Choose a platform</option>
              {platforms.map((p) => (
                <option key={p.key} value={p.key}>
                  {p.label}
                </option>
              ))}
            </select>
            <FieldError>{errors.platform}</FieldError>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-series`}>Release series</label>
            <input
              id={`${formId}-series`}
              className="form-input"
              value={series}
              onChange={(e) => {
                setSeries(e.target.value);
                clear('series');
              }}
              onBlur={() => blur('series')}
              maxLength={40}
              placeholder="17.9 (covers 17.9.x)"
              aria-invalid={!!errors.series}
            />
            <FieldError>{errors.series}</FieldError>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-eol`}>End of life (security fixes stop)</label>
            <input
              id={`${formId}-eol`}
              className="form-input"
              value={eolDate}
              onChange={(e) => {
                setEolDate(e.target.value);
                clear('eol_date');
              }}
              onBlur={() => blur('eol_date')}
              placeholder="YYYY-MM-DD"
              aria-invalid={!!errors.eol_date}
            />
            <FieldError>{errors.eol_date}</FieldError>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-release`}>
              Released <span className="text-muted">(optional)</span>
            </label>
            <input
              id={`${formId}-release`}
              className="form-input"
              value={releaseDate}
              onChange={(e) => {
                setReleaseDate(e.target.value);
                clear('release_date');
              }}
              onBlur={() => blur('release_date')}
              placeholder="YYYY-MM-DD"
              aria-invalid={!!errors.release_date}
            />
            <FieldError>{errors.release_date}</FieldError>
          </div>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-url`}>
            URL <span className="text-muted">(optional)</span>
          </label>
          <input
            id={`${formId}-url`}
            className="form-input"
            value={url}
            onChange={(e) => {
              setUrl(e.target.value);
              clear('url');
            }}
            onBlur={() => blur('url')}
            maxLength={500}
            placeholder="https://vendor.example.com/end-of-life"
            aria-invalid={!!errors.url}
          />
          <FieldError>{errors.url}</FieldError>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-notes`}>
            Notes <span className="text-muted">(optional)</span>
          </label>
          <textarea
            id={`${formId}-notes`}
            className="form-textarea"
            rows={2}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            maxLength={2000}
          />
        </div>
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enabled
          (devices on this series get its status)
        </label>
      </form>
    </Modal>
  );
}
