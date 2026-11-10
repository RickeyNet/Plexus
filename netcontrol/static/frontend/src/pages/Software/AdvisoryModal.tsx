import { FormEvent, useId, useState } from 'react';

import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import {
  type SoftwareAdvisory,
  type SoftwarePlatformInfo,
  useSaveSoftwareAdvisory,
} from '@/api/software';

import { parseVersionList } from './helpers';

interface Props {
  advisory: SoftwareAdvisory | null;
  platforms: SoftwarePlatformInfo[];
  severities: string[];
  onClose: () => void;
}

export function AdvisoryModal({ advisory, platforms, severities, onClose }: Props) {
  const save = useSaveSoftwareAdvisory();
  const isEdit = advisory != null;

  const [advisoryId, setAdvisoryId] = useState(advisory?.advisory_id ?? '');
  const [title, setTitle] = useState(advisory?.title ?? '');
  const [severity, setSeverity] = useState(advisory?.severity ?? 'high');
  const [cvss, setCvss] = useState(advisory?.cvss == null ? '' : String(advisory.cvss));
  const [platform, setPlatform] = useState(advisory?.platform ?? '');
  const [productMatch, setProductMatch] = useState(advisory?.product_match ?? '');
  const [affected, setAffected] = useState((advisory?.affected_versions ?? []).join('\n'));
  const [fixed, setFixed] = useState((advisory?.fixed_versions ?? []).join('\n'));
  const [cves, setCves] = useState((advisory?.cves ?? []).join('\n'));
  const [url, setUrl] = useState(advisory?.url ?? '');
  const [published, setPublished] = useState(advisory?.published ?? '');
  const [summary, setSummary] = useState(advisory?.summary ?? '');
  const [enabled, setEnabled] = useState(advisory?.enabled ?? true);
  const [errors, setErrors] = useState<{ advisoryId?: string; affected?: string; cvss?: string }>({});
  const [saveError, setSaveError] = useState<string | null>(null);
  const formId = useId();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setErrors({});
    setSaveError(null);
    const affected_versions = parseVersionList(affected);
    if (!advisoryId.trim()) {
      setErrors({ advisoryId: 'An advisory ID is required.' });
      return;
    }
    if (affected_versions.length === 0) {
      setErrors({ affected: 'List at least one affected version.' });
      return;
    }
    const cvssNumber = cvss.trim() === '' ? null : Number(cvss);
    if (cvssNumber != null && (!Number.isFinite(cvssNumber) || cvssNumber < 0 || cvssNumber > 10)) {
      setErrors({ cvss: 'CVSS must be a number between 0 and 10.' });
      return;
    }
    try {
      await save.mutateAsync({
        existing: isEdit,
        payload: {
          advisory_id: advisoryId.trim(),
          title: title.trim(),
          severity,
          cvss: cvssNumber,
          platform,
          product_match: productMatch.trim(),
          affected_versions,
          fixed_versions: parseVersionList(fixed),
          cves: parseVersionList(cves.replace(/,/g, '\n')),
          url: url.trim(),
          published: published.trim(),
          summary: summary.trim(),
          enabled,
        },
      });
      onClose();
    } catch (err) {
      setSaveError((err as Error).message);
    }
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={isEdit ? `Edit ${advisory.advisory_id}` : 'Add Advisory'}
      size="medium"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={save.isPending}>
            {save.isPending ? 'Saving…' : isEdit ? 'Save Advisory' : 'Add Advisory'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={submit}>
        {saveError && <Callout tone="danger">{saveError}</Callout>}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 1rem' }}>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-advisory-id`}>Advisory ID</label>
            <input
              id={`${formId}-advisory-id`}
              className="form-input"
              value={advisoryId}
              onChange={(e) => {
                setAdvisoryId(e.target.value);
                setErrors((prev) => ({ ...prev, advisoryId: undefined }));
              }}
              disabled={isEdit}
              required
              maxLength={120}
              placeholder="cisco-sa-… or CVE-…"
              aria-invalid={!!errors.advisoryId}
            />
            <FieldError>{errors.advisoryId}</FieldError>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-severity`}>Severity</label>
            <select id={`${formId}-severity`} className="form-select" value={severity} onChange={(e) => setSeverity(e.target.value)}>
              {severities.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-title`}>Title</label>
          <input
            id={`${formId}-title`}
            className="form-input"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            maxLength={300}
            placeholder="What the advisory is about"
          />
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0 1rem' }}>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-platform`}>
              Platform <span className="text-muted">(blank = any)</span>
            </label>
            <select id={`${formId}-platform`} className="form-select" value={platform} onChange={(e) => setPlatform(e.target.value)}>
              <option value="">Any platform</option>
              {platforms.map((p) => (
                <option key={p.key} value={p.key}>
                  {p.label}
                </option>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-model-contains`}>
              Model contains <span className="text-muted">(optional)</span>
            </label>
            <input
              id={`${formId}-model-contains`}
              className="form-input"
              value={productMatch}
              onChange={(e) => setProductMatch(e.target.value)}
              maxLength={120}
              placeholder="e.g. C9300"
            />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-cvss`}>
              CVSS <span className="text-muted">(optional)</span>
            </label>
            <input
              id={`${formId}-cvss`}
              className="form-input"
              value={cvss}
              onChange={(e) => {
                setCvss(e.target.value);
                setErrors((prev) => ({ ...prev, cvss: undefined }));
              }}
              inputMode="decimal"
              placeholder="9.8"
              aria-invalid={!!errors.cvss}
            />
            <FieldError>{errors.cvss}</FieldError>
          </div>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 1rem' }}>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-affected-versions`}>Affected versions, one per line</label>
            <textarea
              id={`${formId}-affected-versions`}
              className="form-textarea"
              rows={5}
              value={affected}
              onChange={(e) => {
                setAffected(e.target.value);
                setErrors((prev) => ({ ...prev, affected: undefined }));
              }}
              placeholder={'17.9.4a\n<17.6.5\n17.3.*\n16.12..16.12.9, !=16.12.5'}
              required
              aria-invalid={!!errors.affected}
            />
            <FieldError>{errors.affected}</FieldError>
            <div className="text-muted" style={{ fontSize: '0.82em', marginTop: '0.25rem' }}>
              Exact version, prefix with <code>*</code>, comparison (<code>&lt;</code>, <code>&lt;=</code>,{' '}
              <code>&gt;</code>, <code>&gt;=</code>, <code>!=</code>) or range <code>a..b</code>. Comma joins
              constraints that must all hold; each line is checked on its own.
            </div>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-fixed-versions`}>
              Fixed versions <span className="text-muted">(optional, one per line)</span>
            </label>
            <textarea
              id={`${formId}-fixed-versions`}
              className="form-textarea"
              rows={5}
              value={fixed}
              onChange={(e) => setFixed(e.target.value)}
              placeholder={'17.6.5\n17.9.5'}
            />
          </div>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 1rem' }}>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-cves`}>
              CVEs <span className="text-muted">(optional)</span>
            </label>
            <input
              id={`${formId}-cves`}
              className="form-input"
              value={cves}
              onChange={(e) => setCves(e.target.value)}
              placeholder="CVE-2026-0001, CVE-2026-0002"
            />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-published`}>
              Published <span className="text-muted">(optional)</span>
            </label>
            <input
              id={`${formId}-published`}
              className="form-input"
              value={published}
              onChange={(e) => setPublished(e.target.value)}
              maxLength={40}
              placeholder="2026-09-30"
            />
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
            onChange={(e) => setUrl(e.target.value)}
            maxLength={500}
            placeholder="https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/…"
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-summary`}>
            Summary <span className="text-muted">(optional)</span>
          </label>
          <textarea
            id={`${formId}-summary`}
            className="form-textarea"
            rows={3}
            value={summary}
            onChange={(e) => setSummary(e.target.value)}
            maxLength={4000}
          />
        </div>
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enabled
          (devices are checked against this advisory)
        </label>
      </form>
    </Modal>
  );
}
