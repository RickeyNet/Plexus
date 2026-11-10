import { useId, useState, type FormEvent } from 'react';

import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import {
  useCreateHostTemplate,
  useGraphTemplates,
  useHostTemplate,
  useLinkHostTemplateGraph,
  useUnlinkHostTemplateGraph,
  useUpdateHostTemplate,
} from '@/api/graphTemplates';

import { linkDiff, parseDeviceTypes, splitDeviceTypes } from './helpers';

interface Props {
  mode: 'create' | 'edit' | null;
  templateId: number | null;
  onClose: () => void;
}

export function HostTemplateModal({ mode, templateId, onClose }: Props) {
  const formId = useId();
  const isOpen = mode != null;
  const query = useHostTemplate(mode === 'edit' ? templateId : null);
  const graphTemplates = useGraphTemplates();
  const createMut = useCreateHostTemplate();
  const updateMut = useUpdateHostTemplate();
  const linkMut = useLinkHostTemplateGraph();
  const unlinkMut = useUnlinkHostTemplateGraph();

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [deviceTypes, setDeviceTypes] = useState('');
  const [autoApply, setAutoApply] = useState(true);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [nameError, setNameError] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  // The template id once saved and the links the server is known to hold. A
  // create whose links partly fail keeps the modal open; the next Save then
  // updates that template instead of creating a second one.
  const [savedId, setSavedId] = useState<number | null>(null);
  const [linked, setLinked] = useState<Set<number>>(new Set());

  // Seed form fields when the modal opens or the template first loads. A
  // refetch after a save only refreshes the known links, so a selection
  // whose save failed stays ticked for the retry.
  const [prevSeed, setPrevSeed] = useState<{ mode: typeof mode; data: typeof query.data }>({
    mode,
    data: query.data,
  });
  if (prevSeed.mode !== mode || prevSeed.data !== query.data) {
    const opened = prevSeed.mode !== mode;
    setPrevSeed({ mode, data: query.data });
    if (opened) {
      setNameError(null);
      setSaveError(null);
      setSavedId(null);
    }
    if (mode === 'create' && opened) {
      setName(''); setDescription(''); setDeviceTypes(''); setAutoApply(true);
      setSelected(new Set()); setLinked(new Set());
    } else if (mode === 'edit' && query.data) {
      const ht = query.data;
      const ids = new Set((ht.graph_templates ?? []).map((g) => g.id));
      setLinked(ids);
      if (opened || prevSeed.data == null) {
        setName(ht.name ?? '');
        setDescription(ht.description ?? '');
        setDeviceTypes(parseDeviceTypes(ht.device_types).join(', '));
        setAutoApply(!!ht.auto_apply);
        setSelected(ids);
      }
    }
  }

  function toggle(id: number, on: boolean) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (on) next.add(id); else next.delete(id);
      return next;
    });
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSaveError(null);
    if (!name.trim()) {
      setNameError('Name is required');
      return;
    }
    const data = {
      name: name.trim(),
      description: description.trim(),
      device_types: JSON.stringify(splitDeviceTypes(deviceTypes)),
      auto_apply: autoApply,
    };
    setSaving(true);
    try {
      let id = mode === 'edit' ? templateId : savedId;
      if (id != null) {
        await updateMut.mutateAsync({ id, data });
      } else {
        id = (await createMut.mutateAsync(data)).id;
        setSavedId(id);
      }
      const hostTemplateId = id as number;
      const { toLink, toUnlink } = linkDiff(linked, selected);
      const nowLinked = new Set(linked);
      const failures: string[] = [];
      const nameOf = (gid: number) =>
        graphTemplates.data?.graph_templates.find((g) => g.id === gid)?.name ?? `#${gid}`;
      await Promise.all([
        ...toLink.map((gid) =>
          linkMut.mutateAsync({ hostTemplateId, graphTemplateId: gid }).then(
            () => { nowLinked.add(gid); },
            (err: unknown) => { failures.push(`assign "${nameOf(gid)}": ${(err as Error).message}`); },
          ),
        ),
        ...toUnlink.map((gid) =>
          unlinkMut.mutateAsync({ hostTemplateId, graphTemplateId: gid }).then(
            () => { nowLinked.delete(gid); },
            (err: unknown) => { failures.push(`remove "${nameOf(gid)}": ${(err as Error).message}`); },
          ),
        ),
      ]);
      setLinked(nowLinked);
      if (failures.length) {
        setSaveError(`The host template was saved, but some graph template changes failed - ${failures.join('; ')}. Save again to retry.`);
        return;
      }
      onClose();
    } catch (err) {
      setSaveError((err as Error).message);
    } finally {
      setSaving(false);
    }
  }

  const loading = mode === 'edit' && query.isPending;
  const loadError = mode === 'edit' ? query.error : null;
  const allGraphTemplates = graphTemplates.data?.graph_templates ?? [];

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={mode === 'edit' ? 'Edit Host Template' : 'New Host Template'}
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          {!loading && !loadError && (
            <button type="submit" form={formId} className="btn btn-primary" disabled={saving}>
              {saving ? 'Saving…' : mode === 'edit' || savedId != null ? 'Save' : 'Create'}
            </button>
          )}
        </>
      }
    >
      {loading && <LoadingState />}
      {loadError && <Callout tone="danger">Failed to load the host template: {(loadError as Error).message}</Callout>}
      {!loading && !loadError && (
        <form id={formId} onSubmit={handleSubmit}>
          {saveError && <Callout tone="danger">{saveError}</Callout>}
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-name`}>Name</label>
            <input
              id={`${formId}-name`}
              className="form-input"
              value={name}
              onChange={(e) => {
                setName(e.target.value);
                setNameError(null);
              }}
              required
              aria-invalid={!!nameError}
            />
            <FieldError>{nameError}</FieldError>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-description`}>Description</label>
            <input id={`${formId}-description`} className="form-input" value={description} onChange={(e) => setDescription(e.target.value)} />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-device-types`}>Device Types (comma-separated, leave empty for all)</label>
            <input id={`${formId}-device-types`} className="form-input" value={deviceTypes} onChange={(e) => setDeviceTypes(e.target.value)} placeholder="e.g. cisco_ios, cisco_nxos" />
          </div>
          <div className="form-group">
            <label><input type="checkbox" checked={autoApply} onChange={(e) => setAutoApply(e.target.checked)} /> Auto-apply to matching devices</label>
          </div>
          <fieldset className="form-group" style={{ border: 'none', padding: 0, margin: 0 }}>
            <legend className="form-label">Graph Templates ({selected.size} selected)</legend>
            {graphTemplates.isPending && <LoadingState />}
            {graphTemplates.error && (
              <Callout tone="danger">Failed to load graph templates: {(graphTemplates.error as Error).message}</Callout>
            )}
            {graphTemplates.data && (allGraphTemplates.length === 0 ? (
              <p className="text-muted" style={{ fontSize: '0.85rem' }}>No graph templates exist yet.</p>
            ) : (
              <div style={{ maxHeight: 240, overflowY: 'auto', display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: '0.25rem 1rem' }}>
                {allGraphTemplates.map((g) => (
                  <label key={g.id} style={{ display: 'flex', gap: '0.4rem', alignItems: 'center', fontSize: '0.85rem' }}>
                    <input type="checkbox" checked={selected.has(g.id)} onChange={(e) => toggle(g.id, e.target.checked)} />
                    <span>{g.name}</span>
                    <span className="text-muted">({g.scope})</span>
                  </label>
                ))}
              </div>
            ))}
            <p className="text-muted" style={{ fontSize: '0.8rem', margin: '0.35rem 0 0' }}>
              Only device-scoped templates are applied through a host template. Interface-scoped templates are added to every device, one graph per interface, when its interfaces are polled.
            </p>
          </fieldset>
        </form>
      )}
    </Modal>
  );
}
