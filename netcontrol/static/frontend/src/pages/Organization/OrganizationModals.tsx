import { useId, useState } from 'react';

import {
  type Region,
  type Tenant,
  type TenantGroup,
  useRegions,
  useSaveRegion,
  useSaveTenant,
  useSaveTenantGroup,
  useTenantGroups,
} from '@/api/organization';
import { DescriptionInput, SaveFailure } from '@/components/CatalogueParts';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import { NameInput } from '@/components/NameInput';
import { idToSelect, selectToId } from '@/lib/deviceModel';
import { treeOptions } from '@/lib/organization';
import { runSave } from '@/lib/recordSave';
import { serverFieldErrors } from '@/lib/serverFieldErrors';
import { useNameField } from '@/lib/useNameField';

export const ORG_NAME_MAX = 100;

/**
 * Creates or edits a region (`kind` region) or a tenant group: name,
 * parent and description. The parent list leaves out the node itself and
 * everything under it, so a move cannot make a cycle (the server refuses one
 * too, with a 422 on `parent_id`).
 */
export function TreeNodeModal({
  kind,
  node,
  defaultParentId = null,
  onClose,
}: {
  kind: 'region' | 'tenant_group';
  node: Region | TenantGroup | null;
  defaultParentId?: number | null;
  onClose: () => void;
}) {
  const id = useId();
  const what = kind === 'region' ? 'region' : 'tenant group';
  const regionsQ = useRegions(kind === 'region');
  const groupsQ = useTenantGroups();
  const saveRegion = useSaveRegion();
  const saveGroup = useSaveTenantGroup();
  const save = kind === 'region' ? saveRegion : saveGroup;
  const nodes = (kind === 'region' ? regionsQ.data : groupsQ.data) ?? [];
  const name = useNameField(node?.name ?? '', ORG_NAME_MAX, 'Name', (n) =>
    kind === 'region' ? `A region named "${n}" already exists under this parent.` : `A tenant group named "${n}" already exists.`,
  );
  const [parentId, setParentId] = useState<number | null>(node ? node.parent_id : defaultParentId);
  const [description, setDescription] = useState(node?.description ?? '');
  const [failure, setFailure] = useState<string | null>(null);
  const [serverErrors, setServerErrors] = useState<Record<string, string>>({});

  const submit = () => {
    name.touch();
    if (name.error) return;
    setServerErrors({});
    const data = { name: name.trimmed, parent_id: parentId, description: description.trim() };
    void runSave(
      () => save.mutateAsync({ id: node?.id ?? null, data }),
      name,
      setFailure,
      onClose,
      (err) => {
        const fields = serverFieldErrors(err);
        setServerErrors(fields);
        return Object.keys(fields).length > 0;
      },
    );
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      size="small"
      title={node ? `Edit ${what} ${node.name}` : `Add ${what}`}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={node ? `Save ${what}` : `Add ${what}`}
          primaryBusy={save.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      <SaveFailure what={what} message={failure} />
      <NameInput
        id={id}
        label="Name"
        field={name}
        max={ORG_NAME_MAX}
        help={kind === 'region' ? 'Unique among the regions of the same parent, ignoring case.' : 'Names are unique, ignoring case.'}
      />
      <FieldError>{serverErrors.name}</FieldError>
      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-parent`}>
          Parent {what}
        </label>
        <select
          id={`${id}-parent`}
          className="form-select"
          value={idToSelect(parentId)}
          aria-invalid={!!serverErrors.parent_id}
          aria-describedby={`${id}-parent-error`}
          onChange={(e) => {
            setParentId(selectToId(e.target.value));
            setServerErrors((prev) => ({ ...prev, parent_id: '' }));
          }}
        >
          <option value="">None (top level)</option>
          {treeOptions(nodes, node?.id).map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
        <FieldError id={`${id}-parent-error`}>{serverErrors.parent_id}</FieldError>
      </div>
      <DescriptionInput
        id={id}
        value={description}
        error={serverErrors.description}
        onChange={(v) => {
          setDescription(v);
          setServerErrors((prev) => ({ ...prev, description: '' }));
        }}
      />
    </Modal>
  );
}

/** Creates or edits a tenant: name, group, description and comments. */
export function TenantModal({ tenant, onClose }: { tenant: Tenant | null; onClose: () => void }) {
  const id = useId();
  const groupsQ = useTenantGroups();
  const save = useSaveTenant();
  const name = useNameField(tenant?.name ?? '', ORG_NAME_MAX, 'Name', (n) => `A tenant named "${n}" already exists.`);
  const [groupId, setGroupId] = useState<number | null>(tenant?.group_id ?? null);
  const [description, setDescription] = useState(tenant?.description ?? '');
  const [comments, setComments] = useState(tenant?.comments ?? '');
  const [failure, setFailure] = useState<string | null>(null);
  const [serverErrors, setServerErrors] = useState<Record<string, string>>({});

  const submit = () => {
    name.touch();
    if (name.error) return;
    setServerErrors({});
    const data = { name: name.trimmed, group_id: groupId, description: description.trim(), comments: comments.trim() };
    void runSave(
      () => save.mutateAsync({ id: tenant?.id ?? null, data }),
      name,
      setFailure,
      onClose,
      (err) => {
        const fields = serverFieldErrors(err);
        setServerErrors(fields);
        return Object.keys(fields).length > 0;
      },
    );
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      size="small"
      title={tenant ? `Edit tenant ${tenant.name}` : 'Add tenant'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={tenant ? 'Save tenant' : 'Add tenant'}
          primaryBusy={save.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      <SaveFailure what="tenant" message={failure} />
      <NameInput id={id} label="Name" field={name} max={ORG_NAME_MAX} help="Names are unique, ignoring case." />
      <FieldError>{serverErrors.name}</FieldError>
      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-group`}>
          Tenant group
        </label>
        <select
          id={`${id}-group`}
          className="form-select"
          value={idToSelect(groupId)}
          aria-invalid={!!serverErrors.group_id}
          aria-describedby={`${id}-group-error`}
          onChange={(e) => {
            setGroupId(selectToId(e.target.value));
            setServerErrors((prev) => ({ ...prev, group_id: '' }));
          }}
        >
          <option value="">No group</option>
          {treeOptions(groupsQ.data ?? []).map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
        <FieldError id={`${id}-group-error`}>{serverErrors.group_id}</FieldError>
      </div>
      <DescriptionInput
        id={id}
        value={description}
        error={serverErrors.description}
        onChange={(v) => {
          setDescription(v);
          setServerErrors((prev) => ({ ...prev, description: '' }));
        }}
      />
      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-comments`}>
          Comments (optional)
        </label>
        <textarea
          id={`${id}-comments`}
          className="form-input"
          rows={3}
          value={comments}
          maxLength={10000}
          aria-invalid={!!serverErrors.comments}
          onChange={(e) => {
            setComments(e.target.value);
            setServerErrors((prev) => ({ ...prev, comments: '' }));
          }}
        />
        <FieldError>{serverErrors.comments}</FieldError>
      </div>
    </Modal>
  );
}
