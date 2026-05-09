import { useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';

import { apiRequest } from '@/api/client';
import { useCredentials } from '@/api/compliance';
import {
  type UpgradeCampaign,
  type UpgradeCampaignInput,
  type UpgradeCampaignOptions,
  type UpgradeImage,
  useCreateUpgradeCampaign,
  useUpdateUpgradeCampaign,
  useUpgradeCampaign,
  useUpgradeImages,
} from '@/api/upgrades';
import { Modal } from '@/components/Modal';

interface Host {
  id: number;
  hostname?: string;
  ip_address: string;
  model?: string | null;
}

interface Group {
  id: number;
  name: string;
  hosts?: Host[];
}

function useInventoryGroupsWithHosts() {
  return useQuery({
    queryKey: ['inventory-groups', 'with-hosts'],
    queryFn: () => apiRequest<Group[]>('/inventory?include_hosts=true'),
  });
}

interface Props {
  mode: 'create' | 'edit';
  campaignId?: number;
  onClose: () => void;
}

interface ImageMapRow {
  pattern: string;
  image: string;
}

const DEFAULT_OPTIONS: Required<UpgradeCampaignOptions> = {
  skip_backup: false,
  skip_md5: false,
  skip_health_check: false,
  verify_upgrade: true,
  parallel: 4,
  retries: 2,
};

function parseObject(value: unknown): Record<string, unknown> {
  if (typeof value === 'string') {
    try {
      return JSON.parse(value) as Record<string, unknown>;
    } catch {
      return {};
    }
  }
  if (value && typeof value === 'object') return value as Record<string, unknown>;
  return {};
}

function autoSelectImage(pattern: string, images: UpgradeImage[]): string {
  if (!pattern) return images[0]?.filename ?? '';
  const match = images.find((img) =>
    (img.model_pattern || '').toLowerCase().includes(pattern.toLowerCase()),
  );
  return (match || images[0])?.filename ?? '';
}

export function CampaignFormModal({ mode, campaignId, onClose }: Props) {
  const isEdit = mode === 'edit';
  const create = useCreateUpgradeCampaign();
  const update = useUpdateUpgradeCampaign();
  const imagesQ = useUpgradeImages();
  const groupsQ = useInventoryGroupsWithHosts();
  const credsQ = useCredentials();
  const campaignQ = useUpgradeCampaign(isEdit ? campaignId ?? null : null);

  const images = useMemo(() => imagesQ.data || [], [imagesQ.data]);
  const groups = groupsQ.data || [];
  const creds = credsQ.data || [];
  const existing: UpgradeCampaign | undefined = isEdit ? campaignQ.data : undefined;

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [credentialId, setCredentialId] = useState<number | ''>('');
  const [imageMapRows, setImageMapRows] = useState<ImageMapRow[]>([
    { pattern: '9200', image: '' },
  ]);
  const [hostIds, setHostIds] = useState<Set<number>>(new Set());
  const [adHocIps, setAdHocIps] = useState('');
  const [options, setOptions] = useState<Required<UpgradeCampaignOptions>>(
    DEFAULT_OPTIONS,
  );
  const [error, setError] = useState<string | null>(null);
  const [hydrated, setHydrated] = useState(false);

  const lockedIps = useMemo(() => {
    const set = new Set<string>();
    if (!existing) return set;
    for (const d of existing.devices) {
      if (
        d.phase === 'running' ||
        d.prestage_status === 'running' ||
        d.transfer_status === 'running' ||
        d.activate_status === 'running' ||
        d.verify_status === 'running'
      ) {
        set.add(d.ip_address);
      }
    }
    return set;
  }, [existing]);

  // Hydrate state from campaign + apply default image once images load
  useEffect(() => {
    if (hydrated) return;
    if (isEdit) {
      if (!existing || imagesQ.isPending) return;
      const opts = parseObject(existing.options);
      const map = parseObject(existing.image_map);
      const rows: ImageMapRow[] = Object.entries(map).map(([k, v]) => ({
        pattern: k,
        image: String(v),
      }));
      setName(existing.name);
      setDescription(existing.description || '');
      setCredentialId(
        typeof opts.credential_id === 'number' ? opts.credential_id : '',
      );
      setImageMapRows(rows.length ? rows : [{ pattern: '', image: images[0]?.filename ?? '' }]);
      setOptions({
        skip_backup: Boolean(opts.skip_backup),
        skip_md5: Boolean(opts.skip_md5),
        skip_health_check: Boolean(opts.skip_health_check),
        verify_upgrade: opts.verify_upgrade !== false,
        parallel: typeof opts.parallel === 'number' ? opts.parallel : 4,
        retries: typeof opts.retries === 'number' ? opts.retries : 2,
      });
      const ids = new Set<number>();
      const ips: string[] = [];
      for (const d of existing.devices) {
        if (d.host_id) ids.add(d.host_id);
        else ips.push(d.ip_address);
      }
      setHostIds(ids);
      setAdHocIps(ips.join('\n'));
      setHydrated(true);
    } else {
      if (imagesQ.isPending) return;
      setImageMapRows([
        { pattern: '9200', image: autoSelectImage('9200', images) },
      ]);
      setHydrated(true);
    }
    // `images` intentionally omitted: hydration must run once per open and a
    // background images refetch should not overwrite user-edited rows.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hydrated, isEdit, existing, imagesQ.isPending]);

  const setRow = (i: number, patch: Partial<ImageMapRow>) => {
    setImageMapRows((rows) =>
      rows.map((r, idx) => (idx === i ? { ...r, ...patch } : r)),
    );
  };

  const addRow = () => {
    setImageMapRows((rows) => [
      ...rows,
      { pattern: '', image: images[0]?.filename ?? '' },
    ]);
  };

  const removeRow = (i: number) => {
    setImageMapRows((rows) => rows.filter((_, idx) => idx !== i));
  };

  const toggleHost = (id: number, checked: boolean) => {
    setHostIds((prev) => {
      const next = new Set(prev);
      if (checked) next.add(id);
      else next.delete(id);
      return next;
    });
  };

  const toggleGroup = (group: Group, checked: boolean) => {
    const editableHosts = (group.hosts || []).filter(
      (h) => !lockedIps.has(h.ip_address),
    );
    setHostIds((prev) => {
      const next = new Set(prev);
      for (const h of editableHosts) {
        if (checked) next.add(h.id);
        else next.delete(h.id);
      }
      return next;
    });
  };

  const groupCheckboxState = (group: Group): 'all' | 'some' | 'none' => {
    const hosts = group.hosts || [];
    if (hosts.length === 0) return 'none';
    const editable = hosts.filter((h) => !lockedIps.has(h.ip_address));
    const scope = editable.length > 0 ? editable : hosts;
    const checked = scope.filter((h) => hostIds.has(h.id)).length;
    if (checked === 0) return 'none';
    if (checked === scope.length) return 'all';
    return 'some';
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const map: Record<string, string> = {};
    for (const r of imageMapRows) {
      const p = r.pattern.trim();
      if (p && r.image) map[p] = r.image;
    }
    if (Object.keys(map).length === 0) {
      setError('Add at least one image mapping');
      return;
    }
    if (!credentialId) {
      setError('Select a credential');
      return;
    }
    const ips = adHocIps
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (hostIds.size === 0 && ips.length === 0) {
      setError('Select at least one device or enter ad-hoc IPs');
      return;
    }

    const body: UpgradeCampaignInput = {
      name,
      description,
      image_map: map,
      credential_id: Number(credentialId),
      host_ids: Array.from(hostIds),
      ad_hoc_ips: ips,
      options,
    };

    const onError = (err: unknown) => setError((err as Error).message);
    if (isEdit && campaignId != null) {
      update.mutate(
        { id: campaignId, body },
        { onSuccess: () => onClose(), onError },
      );
    } else {
      create.mutate(body, { onSuccess: () => onClose(), onError });
    }
  };

  const isPending = isEdit
    ? campaignQ.isPending || imagesQ.isPending || groupsQ.isPending || credsQ.isPending
    : imagesQ.isPending || groupsQ.isPending || credsQ.isPending;
  const isSubmitting = create.isPending || update.isPending;
  const title = isEdit ? 'Edit Campaign' : 'Create Upgrade Campaign';

  return (
    <Modal isOpen onClose={onClose} title={title} size="large">
      {isPending ? (
        <p className="text-muted">Loading…</p>
      ) : (
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Campaign Name</label>
            <input
              className="form-input"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Q2 2026 IOS-XE 17.15 Upgrade"
            />
          </div>
          <div className="form-group">
            <label className="form-label">Description</label>
            <textarea
              className="form-input"
              rows={2}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Optional description…"
            />
          </div>

          <fieldset
            style={{
              border: '1px solid var(--glass-border)',
              borderRadius: 8,
              padding: '1rem',
              marginBottom: '1rem',
            }}
          >
            <legend style={{ fontWeight: 600, padding: '0 0.5rem' }}>
              Image Map
            </legend>
            <p style={{ fontSize: '0.85em', opacity: 0.7, marginTop: 0 }}>
              Map model patterns to images. Patterns are matched longest-first.
            </p>
            {imageMapRows.map((row, i) => (
              <div
                key={i}
                style={{
                  display: 'flex',
                  gap: '0.5rem',
                  marginBottom: '0.5rem',
                }}
              >
                <input
                  className="form-input"
                  placeholder="Model pattern (e.g. 9200)"
                  value={row.pattern}
                  onChange={(e) => setRow(i, { pattern: e.target.value })}
                  style={{ flex: 1 }}
                />
                <select
                  className="form-select"
                  value={row.image}
                  onChange={(e) => setRow(i, { image: e.target.value })}
                  style={{ flex: 2 }}
                >
                  {images.length === 0 && <option value="">No images uploaded</option>}
                  {images.map((img) => (
                    <option key={img.id} value={img.filename}>
                      {img.filename} ({img.model_pattern || 'no pattern'} / v
                      {img.version || '?'})
                    </option>
                  ))}
                </select>
                <button
                  type="button"
                  className="btn btn-sm btn-secondary"
                  onClick={() => removeRow(i)}
                  aria-label="Remove mapping"
                >
                  ×
                </button>
              </div>
            ))}
            <button
              type="button"
              className="btn btn-sm btn-secondary"
              onClick={addRow}
            >
              + Add Mapping
            </button>
          </fieldset>

          <div className="form-group">
            <label className="form-label">Credential</label>
            <select
              className="form-select"
              required
              value={credentialId}
              onChange={(e) =>
                setCredentialId(e.target.value ? Number(e.target.value) : '')
              }
            >
              <option value="">Select credential…</option>
              {creds.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name || `Credential ${c.id}`}
                </option>
              ))}
            </select>
          </div>

          <fieldset
            style={{
              border: '1px solid var(--glass-border)',
              borderRadius: 8,
              padding: '1rem',
              marginBottom: '1rem',
            }}
          >
            <legend style={{ fontWeight: 600, padding: '0 0.5rem' }}>
              Target Devices
            </legend>
            {lockedIps.size > 0 && (
              <p style={{ fontSize: '0.85em', color: 'var(--warning)', marginTop: 0 }}>
                {lockedIps.size} device(s) are currently running and cannot be
                removed.
              </p>
            )}
            <div style={{ maxHeight: 250, overflowY: 'auto' }}>
              {groups.map((g) => {
                const state = groupCheckboxState(g);
                return (
                  <div key={g.id} style={{ marginBottom: '0.75rem' }}>
                    <label
                      style={{
                        fontWeight: 600,
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.5rem',
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={state === 'all'}
                        ref={(el) => {
                          if (el) el.indeterminate = state === 'some';
                        }}
                        onChange={(e) => toggleGroup(g, e.target.checked)}
                      />
                      {g.name} ({(g.hosts || []).length} hosts)
                    </label>
                    <div style={{ marginLeft: '1.5rem' }}>
                      {(g.hosts || []).map((h) => {
                        const locked = lockedIps.has(h.ip_address);
                        return (
                          <label
                            key={h.id}
                            style={{
                              display: 'flex',
                              alignItems: 'center',
                              gap: '0.5rem',
                              fontSize: '0.9em',
                            }}
                          >
                            <input
                              type="checkbox"
                              checked={hostIds.has(h.id)}
                              disabled={locked}
                              onChange={(e) => toggleHost(h.id, e.target.checked)}
                            />
                            {h.hostname || h.ip_address}{' '}
                            <span style={{ opacity: 0.5 }}>{h.ip_address}</span>
                            {h.model && (
                              <code style={{ fontSize: '0.8em' }}>{h.model}</code>
                            )}
                            {locked && (
                              <span style={{ fontSize: '0.75em', opacity: 0.6 }}>
                                (in progress)
                              </span>
                            )}
                          </label>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>
            <div className="form-group" style={{ marginTop: '0.75rem' }}>
              <label className="form-label">Ad-hoc IPs (one per line)</label>
              <textarea
                className="form-input"
                rows={2}
                value={adHocIps}
                onChange={(e) => setAdHocIps(e.target.value)}
                placeholder={'10.0.1.1\n10.0.1.2'}
              />
            </div>
          </fieldset>

          <fieldset
            style={{
              border: '1px solid var(--glass-border)',
              borderRadius: 8,
              padding: '1rem',
              marginBottom: '1rem',
            }}
          >
            <legend style={{ fontWeight: 600, padding: '0 0.5rem' }}>
              Options
            </legend>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: '0.5rem',
              }}
            >
              {(
                [
                  ['skip_backup', 'Skip config backup'],
                  ['skip_md5', 'Skip MD5 verification'],
                  ['skip_health_check', 'Skip health check'],
                  ['verify_upgrade', 'Verify upgrade after reboot'],
                ] as const
              ).map(([key, label]) => (
                <label
                  key={key}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                  }}
                >
                  <input
                    type="checkbox"
                    checked={options[key]}
                    onChange={(e) =>
                      setOptions((o) => ({ ...o, [key]: e.target.checked }))
                    }
                  />
                  {label}
                </label>
              ))}
            </div>
            <div style={{ display: 'flex', gap: '1rem', marginTop: '0.75rem' }}>
              <div className="form-group" style={{ flex: 1 }}>
                <label className="form-label">Parallel Workers</label>
                <input
                  type="number"
                  className="form-input"
                  min={1}
                  max={8}
                  value={options.parallel}
                  onChange={(e) =>
                    setOptions((o) => ({
                      ...o,
                      parallel: Number(e.target.value) || 4,
                    }))
                  }
                />
              </div>
              <div className="form-group" style={{ flex: 1 }}>
                <label className="form-label">SSH Retries</label>
                <input
                  type="number"
                  className="form-input"
                  min={0}
                  max={5}
                  value={options.retries}
                  onChange={(e) =>
                    setOptions((o) => ({
                      ...o,
                      retries: Number(e.target.value) || 0,
                    }))
                  }
                />
              </div>
            </div>
          </fieldset>

          {error && (
            <p style={{ color: 'var(--danger)', marginTop: '0.5rem' }}>{error}</p>
          )}

          <div
            style={{
              display: 'flex',
              justifyContent: 'flex-end',
              gap: '0.5rem',
            }}
          >
            <button
              type="button"
              className="btn btn-secondary"
              onClick={onClose}
              disabled={isSubmitting}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={isSubmitting}
            >
              {isSubmitting
                ? isEdit
                  ? 'Saving…'
                  : 'Creating…'
                : isEdit
                  ? 'Save Changes'
                  : 'Create Campaign'}
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}
