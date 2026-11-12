import { useState } from 'react';
import { Link } from 'react-router';

import { type CloudProvider, useMerakiOrgs } from '@/api/meraki';
import { Modal } from '@/components/Modal';
import type { AddSourceAccess } from '@/lib/addSource';

import { addSourceOptions } from './addSourceOptions';
import { defaultOptionsFor } from './sourceForm';
import { SourceFormModal } from './SourceFormModal';

/** The form of the chosen organization source, with the server's default options. */
function AddOrgSource({ provider, onClose }: { provider: CloudProvider; onClose: () => void }) {
  const orgs = useMerakiOrgs();
  return (
    <SourceFormModal
      provider={provider}
      existing={null}
      defaultOptions={defaultOptionsFor(provider, orgs.data)}
      onClose={onClose}
    />
  );
}

export interface AddSourceDialogProps {
  access: AddSourceAccess;
  onClose: () => void;
}

/**
 * The app-wide Add source action (sidebar, Dashboard): choose what to
 * connect. An organization source goes on to its form and setup steps right
 * here, on whatever page the user is; a cloud account opens its Add dialog
 * under Cloud Visibility.
 */
export function AddSourceDialog({ access, onClose }: AddSourceDialogProps) {
  const [provider, setProvider] = useState<CloudProvider | null>(null);
  if (provider) return <AddOrgSource provider={provider} onClose={onClose} />;

  const options = addSourceOptions(access);
  return (
    <Modal
      isOpen
      onClose={onClose}
      title="Add a source"
      size="medium"
      footer={
        <button type="button" className="btn btn-secondary" onClick={onClose}>
          Cancel
        </button>
      }
    >
      <p className="text-muted" style={{ marginTop: 0 }}>
        A source is a system Plexus reads your network from. Once added, its credentials are checked, it is collected
        and it appears on the topology map and the Dashboard.
      </p>
      <ul className="add-source-options">
        {options.map((option) => {
          const body = (
            <>
              <strong>{option.label}</strong>
              <span className="text-muted">{option.description}</span>
            </>
          );
          return (
            <li key={option.provider}>
              {option.kind === 'org' ? (
                <button type="button" className="add-source-option" onClick={() => setProvider(option.provider)}>
                  {body}
                </button>
              ) : (
                <Link className="add-source-option" to={option.to} onClick={onClose}>
                  {body}
                </Link>
              )}
            </li>
          );
        })}
      </ul>
      <p className="text-muted" style={{ fontSize: '0.85em', marginBottom: 0 }}>
        {access.cloud && 'Cloud accounts are added under Cloud Visibility, which opens with the form ready. '}
        Switches, routers and other devices you manage directly are added under{' '}
        <Link to="/inventory" onClick={onClose}>
          Inventory
        </Link>
        .
      </p>
    </Modal>
  );
}
