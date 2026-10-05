import { FormEvent, useState } from 'react';

import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';
import { useImportSoftwareAdvisories } from '@/api/software';

import { parseAdvisoryImport } from './helpers';

interface Props {
  onClose: () => void;
}

const EXAMPLE = `[
  {
    "advisory_id": "cisco-sa-example",
    "title": "Example advisory",
    "severity": "high",
    "cvss": 8.6,
    "platform": "ios-xe",
    "affected_versions": ["17.3.*", "<17.6.5"],
    "fixed_versions": ["17.6.5"],
    "cves": ["CVE-2026-0001"],
    "url": "https://example.com/advisory"
  }
]`;

export function ImportAdvisoriesModal({ onClose }: Props) {
  const { alert } = useDialogs();
  const importAdvisories = useImportSoftwareAdvisories();
  const [text, setText] = useState('');
  const [problem, setProblem] = useState('');

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const parsed = parseAdvisoryImport(text);
    if (parsed.error) {
      setProblem(parsed.error);
      return;
    }
    setProblem('');
    try {
      const res = await importAdvisories.mutateAsync(parsed.advisories);
      void alert(`Imported ${res.imported} advisor${res.imported === 1 ? 'y' : 'ies'}.`);
      onClose();
    } catch (err) {
      void alert({ message: (err as Error).message, variant: 'error' });
    }
  };

  return (
    <Modal isOpen onClose={onClose} title="Import Advisories" size="large">
      <form onSubmit={submit}>
        <p className="text-muted" style={{ marginTop: 0 }}>
          Paste a JSON list of advisories (or an object with an <code>advisories</code> list). An advisory with
          the same ID as a stored one replaces it. Only <code>advisory_id</code> and{' '}
          <code>affected_versions</code> are required.
        </p>
        <div className="form-group">
          <textarea
            className="form-textarea"
            rows={14}
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={EXAMPLE}
            spellCheck={false}
            style={{ fontFamily: 'monospace', fontSize: '0.85em' }}
            required
          />
        </div>
        {problem && (
          <div className="text-danger" style={{ marginBottom: '0.75rem' }}>
            {problem}
          </div>
        )}
        <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
          <button type="button" className="btn btn-secondary" onClick={() => setText(EXAMPLE)}>
            Insert Example
          </button>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn btn-primary" disabled={importAdvisories.isPending}>
            {importAdvisories.isPending ? 'Importing…' : 'Import'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
