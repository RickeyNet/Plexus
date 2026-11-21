import { useId, useMemo, useState, type FormEvent } from 'react';

import CodeMirror, { EditorView } from '@uiw/react-codemirror';
import { python } from '@codemirror/lang-python';
import { yaml } from '@codemirror/lang-yaml';
import { dracula } from '@uiw/codemirror-theme-dracula';

import { Badge } from '@/components/Badge';
import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';
import { useAuthStatus } from '@/api/auth';
import { CustomDataError } from '@/api/customData';
import {
  useCreatePlaybook,
  usePlaybook,
  useUpdatePlaybook,
  type JobPermissions,
  type PlaybookType,
  type PlaybookUpdate,
} from '@/api/jobs';
import { useAccessGroups } from '@/api/settings';

import { parseTags } from './helpers';
import { fieldFromRow, rowFromField, validateSchemaRows, type SchemaRow } from './jobInputs';
import { InputSchemaEditor, JobPermissionsEditor } from './PlaybookInputsEditor';

const OPEN_PERMISSIONS: JobPermissions = { run: { roles: [], groups: [] }, commit: { roles: [], groups: [] } };

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
  const formId = useId();
  const isOpen = mode != null;
  const detailQuery = usePlaybook(mode === 'edit' ? playbookId : null);
  const createMut = useCreatePlaybook();
  const updateMut = useUpdatePlaybook();
  const auth = useAuthStatus();
  const isAdmin = auth.data?.role === 'admin';
  const accessGroups = useAccessGroups(isAdmin);

  const [type, setType] = useState<PlaybookType>('python');
  const [name, setName] = useState('');
  const [filename, setFilename] = useState('');
  const [description, setDescription] = useState('');
  const [tagsStr, setTagsStr] = useState('');
  const [content, setContent] = useState(PYTHON_DEFAULT);
  const [contentDirty, setContentDirty] = useState(false);
  const [errors, setErrors] = useState<{ name?: string; filename?: string; content?: string }>({});
  const [saveError, setSaveError] = useState<string | null>(null);
  const [schemaRows, setSchemaRows] = useState<SchemaRow[]>([]);
  const [schemaDirty, setSchemaDirty] = useState(false);
  const [schemaErrors, setSchemaErrors] = useState<Record<string, string>>({});
  const [permissions, setPermissions] = useState<JobPermissions>(OPEN_PERMISSIONS);
  const [permissionsDirty, setPermissionsDirty] = useState(false);
  const [approvalRequired, setApprovalRequired] = useState(false);
  const [approvalDirty, setApprovalDirty] = useState(false);

  const editorExtensions = useMemo(
    () => [
      type === 'ansible' ? yaml() : python(),
      EditorView.contentAttributes.of({ 'aria-labelledby': `${formId}-content` }),
    ],
    [type, formId],
  );

  const [prevMode, setPrevMode] = useState(mode);
  const [prevData, setPrevData] = useState(detailQuery.data);
  if (mode !== prevMode || detailQuery.data !== prevData) {
    setPrevMode(mode);
    setPrevData(detailQuery.data);
    setErrors({});
    setSaveError(null);
    setSchemaErrors({});
    setSchemaDirty(false);
    setPermissionsDirty(false);
    setApprovalDirty(false);
    if (mode === 'create') {
      setType('python'); setName(''); setFilename(''); setDescription('');
      setTagsStr(''); setContent(PYTHON_DEFAULT); setContentDirty(false);
      setSchemaRows([]); setPermissions(OPEN_PERMISSIONS); setApprovalRequired(false);
    } else if (mode === 'edit' && detailQuery.data) {
      const pb = detailQuery.data;
      setType((pb.type as PlaybookType) ?? 'python');
      setName(pb.name ?? '');
      setFilename(pb.filename ?? '');
      setDescription(pb.description ?? '');
      setTagsStr(parseTags(pb.tags).join(', '));
      setContent(pb.content ?? '');
      setContentDirty(false);
      setSchemaRows((pb.input_schema ?? []).map(rowFromField));
      setPermissions(pb.permissions ?? OPEN_PERMISSIONS);
      setApprovalRequired(Boolean(pb.approval_required));
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
    setSaveError(null);
    const nextErrors = {
      name: name.trim() ? undefined : 'Name is required',
      filename: filename.trim() ? undefined : 'Filename is required',
      content: content.trim() ? undefined : 'Content is required',
    };
    const nextSchemaErrors = schemaDirty ? validateSchemaRows(schemaRows) : {};
    setErrors(nextErrors);
    setSchemaErrors(nextSchemaErrors);
    if (nextErrors.name || nextErrors.filename || nextErrors.content) return;
    if (Object.keys(nextSchemaErrors).length > 0) return;
    let fname = filename.trim();
    if (type === 'ansible') {
      if (!/\.(yml|yaml)$/i.test(fname)) fname += '.yml';
    } else if (!fname.endsWith('.py')) {
      fname += '.py';
    }
    const tags = tagsStr.split(',').map((t) => t.trim()).filter(Boolean);
    const data: PlaybookUpdate & { name: string; filename: string; content: string } = {
      name: name.trim(),
      filename: fname,
      description: description.trim(),
      tags,
      content,
      type,
    };
    // Send only what changed: an untouched code-declared schema stays in code.
    if (schemaDirty) data.input_schema = schemaRows.map(fieldFromRow);
    if (isAdmin && permissionsDirty) data.permissions = permissions;
    if (isAdmin && approvalDirty) data.approval_required = approvalRequired;
    const onError = (err: unknown) => {
      if (err instanceof CustomDataError && Object.keys(err.fields).length > 0) {
        const rowErrs = Object.fromEntries(Object.entries(err.fields).filter(([k]) => /^\d+(\.|$)/.test(k)));
        setSchemaErrors(rowErrs);
        const other = Object.entries(err.fields).filter(([k]) => !(k in rowErrs)).map(([, m]) => m);
        setSaveError([err.message, ...other].join(' '));
      } else {
        setSaveError((err as Error).message);
      }
    };
    if (mode === 'edit' && playbookId != null) {
      updateMut.mutate({ id: playbookId, data }, { onSuccess: onClose, onError });
    } else {
      createMut.mutate(data, { onSuccess: onClose, onError });
    }
  }

  const pending = createMut.isPending || updateMut.isPending;
  const extHint = type === 'ansible' ? 'Must end with .yml or .yaml' : 'Must end with .py';

  const loadFailed = mode === 'edit' && detailQuery.error != null && !detailQuery.data;
  const loading = mode === 'edit' && detailQuery.isPending;

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={mode === 'edit' ? 'Edit Task' : 'New Task'}
      size="medium"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          {!loading && !loadFailed && (
            <button type="submit" form={formId} className="btn btn-primary" disabled={pending}>
              {pending ? 'Saving…' : mode === 'edit' ? 'Save' : 'Create'}
            </button>
          )}
        </>
      }
    >
      {loadFailed ? (
        <QueryError what="task" query={detailQuery} />
      ) : loading ? (
        <LoadingState />
      ) : (
        <form id={formId} onSubmit={handleSubmit}>
          {saveError && <Callout tone="danger">{saveError}</Callout>}
          <div className="form-group">
            <label className="form-label" htmlFor={mode === 'edit' ? undefined : `${formId}-type`}>Type</label>
            {mode === 'edit' ? (
              <div>
                <Badge tone={type === 'ansible' ? 'info' : 'primary'}>{type === 'ansible' ? 'Ansible' : 'Python'}</Badge>
              </div>
            ) : (
              <select id={`${formId}-type`} className="form-select" value={type} onChange={(e) => handleTypeChange(e.target.value as PlaybookType)}>
                <option value="python">Python (Netmiko)</option>
                <option value="ansible">Ansible (YAML)</option>
              </select>
            )}
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-name`}>Name</label>
            <input
              id={`${formId}-name`}
              className="form-input"
              value={name}
              onChange={(e) => { setName(e.target.value); setErrors((p) => ({ ...p, name: undefined })); }}
              aria-invalid={!!errors.name}
              required
            />
            <FieldError>{errors.name}</FieldError>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-filename`}>Filename</label>
            <input
              id={`${formId}-filename`}
              className="form-input"
              value={filename}
              onChange={(e) => { setFilename(e.target.value); setErrors((p) => ({ ...p, filename: undefined })); }}
              aria-invalid={!!errors.filename}
              readOnly={!isAdmin}
              required
            />
            <small className="text-muted">{isAdmin ? extHint : 'Only an admin can change the filename or code.'}</small>
            <FieldError>{errors.filename}</FieldError>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-description`}>Description</label>
            <textarea id={`${formId}-description`} className="form-input" value={description} onChange={(e) => setDescription(e.target.value)} rows={3} />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-tags`}>Tags (comma-separated)</label>
            <input id={`${formId}-tags`} className="form-input" value={tagsStr} onChange={(e) => setTagsStr(e.target.value)} placeholder="example, automation" />
          </div>
          <div className="form-group">
            <span className="form-label" id={`${formId}-content`}>{type === 'ansible' ? 'Ansible YAML' : 'Python Code'}</span>
            <CodeMirror
              value={content}
              theme={dracula}
              extensions={editorExtensions}
              readOnly={!isAdmin}
              onChange={(value) => {
                setContent(value);
                setContentDirty(true);
                setErrors((p) => ({ ...p, content: undefined }));
              }}
              basicSetup={{
                lineNumbers: true,
                highlightActiveLine: true,
                bracketMatching: true,
                closeBrackets: true,
                indentOnInput: true,
                tabSize: 4,
              }}
              style={{ fontSize: '0.85rem', border: '1px solid var(--border)', borderRadius: 4 }}
              className="playbook-code-editor"
            />
            <FieldError>{errors.content}</FieldError>
          </div>
          <InputSchemaEditor
            rows={schemaRows}
            onChange={(rows) => { setSchemaRows(rows); setSchemaDirty(true); setSchemaErrors({}); }}
            errors={schemaErrors}
            source={mode === 'edit' ? detailQuery.data?.input_schema_source : undefined}
          />
          <div className="form-group">
            <label className="form-check" htmlFor={`${formId}-approval`}>
              <input
                id={`${formId}-approval`}
                type="checkbox"
                checked={approvalRequired}
                disabled={!isAdmin}
                onChange={(e) => { setApprovalRequired(e.target.checked); setApprovalDirty(true); }}
              />
              Require approval before jobs run
            </label>
            <small className="text-muted">
              Jobs from this task wait in the Approvals tab until a user with job approval rights, other than
              the requester, approves them.{!isAdmin && ' Only an admin can change this.'}
            </small>
          </div>
          {isAdmin && (
            <JobPermissionsEditor
              value={permissions}
              onChange={(next) => { setPermissions(next); setPermissionsDirty(true); }}
              accessGroups={accessGroups.data}
              accessGroupsFailed={accessGroups.isError}
            />
          )}
        </form>
      )}
    </Modal>
  );
}
