import { useMemo, useState, type FormEvent } from 'react';

import CodeMirror from '@uiw/react-codemirror';
import { python } from '@codemirror/lang-python';
import { yaml } from '@codemirror/lang-yaml';
import { dracula } from '@uiw/codemirror-theme-dracula';

import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';
import {
  useCreatePlaybook,
  usePlaybook,
  useUpdatePlaybook,
  type PlaybookType,
} from '@/api/jobs';

import { parseTags } from './helpers';

interface Props {
  mode: 'create' | 'edit' | null;
  playbookId: number | null;
  onClose: () => void;
}

const PYTHON_DEFAULT = `"""
Your playbook description here.

This playbook will be executed on all hosts in the selected inventory group.
"""

import asyncio
from typing import AsyncGenerator

from routes.runner import BasePlaybook, LogEvent, register_playbook


@register_playbook
class MyPlaybook(BasePlaybook):
    filename = "my_playbook.py"
    display_name = "My Playbook"
    description = "Description of what this playbook does"
    tags = ["example"]
    requires_template = False

    async def run(self, hosts, credentials, template_commands=None, dry_run=True):
        yield self.log_info(f"My Playbook - targeting {len(hosts)} device(s)")
        if dry_run:
            yield self.log_warn("*** DRY-RUN MODE - no changes will be made ***")
        for host_info in hosts:
            ip = host_info["ip_address"]
            hostname = host_info.get("hostname", ip)
            yield self.log_info(f"Processing {hostname} ({ip})…", host=hostname)
            await asyncio.sleep(0.1)
            yield self.log_success(f"Finished {hostname}", host=hostname)
        yield self.log_success("Playbook execution complete")
`;

const ANSIBLE_DEFAULT = `---
- name: My Ansible Playbook
  hosts: all
  gather_facts: false
  connection: ansible.netcommon.network_cli

  tasks:
    - name: Show version
      cisco.ios.ios_command:
        commands:
          - show version
      register: result

    - name: Display output
      debug:
        var: result.stdout_lines
`;

export function PlaybookFormModal({ mode, playbookId, onClose }: Props) {
  const { alert } = useDialogs();
  const isOpen = mode != null;
  const detailQuery = usePlaybook(mode === 'edit' ? playbookId : null);
  const createMut = useCreatePlaybook();
  const updateMut = useUpdatePlaybook();

  const [type, setType] = useState<PlaybookType>('python');
  const [name, setName] = useState('');
  const [filename, setFilename] = useState('');
  const [description, setDescription] = useState('');
  const [tagsStr, setTagsStr] = useState('');
  const [content, setContent] = useState(PYTHON_DEFAULT);
  const [contentDirty, setContentDirty] = useState(false);

  const editorExtensions = useMemo(() => [type === 'ansible' ? yaml() : python()], [type]);

  const [prevMode, setPrevMode] = useState(mode);
  const [prevData, setPrevData] = useState(detailQuery.data);
  if (mode !== prevMode || detailQuery.data !== prevData) {
    setPrevMode(mode);
    setPrevData(detailQuery.data);
    if (mode === 'create') {
      setType('python'); setName(''); setFilename(''); setDescription('');
      setTagsStr(''); setContent(PYTHON_DEFAULT); setContentDirty(false);
    } else if (mode === 'edit' && detailQuery.data) {
      const pb = detailQuery.data;
      setType((pb.type as PlaybookType) ?? 'python');
      setName(pb.name ?? '');
      setFilename(pb.filename ?? '');
      setDescription(pb.description ?? '');
      setTagsStr(parseTags(pb.tags).join(', '));
      setContent(pb.content ?? '');
      setContentDirty(false);
    }
  }

  function handleTypeChange(newType: PlaybookType) {
    setType(newType);
    if (mode === 'create' && !contentDirty) {
      setContent(newType === 'ansible' ? ANSIBLE_DEFAULT : PYTHON_DEFAULT);
    }
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim() || !filename.trim() || !content.trim()) {
      void alert('Name, filename, and content are required');
      return;
    }
    let fname = filename.trim();
    if (type === 'ansible') {
      if (!/\.(yml|yaml)$/i.test(fname)) fname += '.yml';
    } else if (!fname.endsWith('.py')) {
      fname += '.py';
    }
    const tags = tagsStr.split(',').map((t) => t.trim()).filter(Boolean);
    const data = {
      name: name.trim(),
      filename: fname,
      description: description.trim(),
      tags,
      content,
      type,
    };
    const onError = (err: unknown) => { void alert({ message: (err as Error).message, variant: 'error' }); };
    if (mode === 'edit' && playbookId != null) {
      updateMut.mutate({ id: playbookId, data }, { onSuccess: onClose, onError });
    } else {
      createMut.mutate(data, { onSuccess: onClose, onError });
    }
  }

  const pending = createMut.isPending || updateMut.isPending;
  const extHint = type === 'ansible' ? 'Must end with .yml or .yaml' : 'Must end with .py';

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={mode === 'edit' ? 'Edit Playbook' : 'New Playbook'} size="large">
      {mode === 'edit' && detailQuery.isPending ? (
        <p className="text-muted">Loading…</p>
      ) : (
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Type</label>
            {mode === 'edit' ? (
              <div>
                <span className="badge" style={{ background: type === 'ansible' ? 'var(--info)' : 'var(--primary)', color: '#fff' }}>
                  {type === 'ansible' ? 'Ansible' : 'Python'}
                </span>
              </div>
            ) : (
              <select className="form-select" value={type} onChange={(e) => handleTypeChange(e.target.value as PlaybookType)}>
                <option value="python">Python (Netmiko)</option>
                <option value="ansible">Ansible (YAML)</option>
              </select>
            )}
          </div>
          <div className="form-group">
            <label className="form-label">Name</label>
            <input className="form-input" value={name} onChange={(e) => setName(e.target.value)} required />
          </div>
          <div className="form-group">
            <label className="form-label">Filename</label>
            <input className="form-input" value={filename} onChange={(e) => setFilename(e.target.value)} required />
            <small className="text-muted">{extHint}</small>
          </div>
          <div className="form-group">
            <label className="form-label">Description</label>
            <textarea className="form-input" value={description} onChange={(e) => setDescription(e.target.value)} rows={3} />
          </div>
          <div className="form-group">
            <label className="form-label">Tags (comma-separated)</label>
            <input className="form-input" value={tagsStr} onChange={(e) => setTagsStr(e.target.value)} placeholder="example, automation" />
          </div>
          <div className="form-group">
            <label className="form-label">{type === 'ansible' ? 'Ansible YAML' : 'Python Code'}</label>
            <CodeMirror
              value={content}
              theme={dracula}
              extensions={editorExtensions}
              onChange={(value) => { setContent(value); setContentDirty(true); }}
              basicSetup={{
                lineNumbers: true,
                highlightActiveLine: true,
                bracketMatching: true,
                closeBrackets: true,
                indentOnInput: true,
                tabSize: 4,
              }}
              style={{ fontSize: '0.85rem', border: '1px solid var(--border, #444)', borderRadius: 4 }}
              className="playbook-code-editor"
            />
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '1rem' }}>
            <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={pending}>
              {pending ? 'Saving…' : mode === 'edit' ? 'Save' : 'Create'}
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}
