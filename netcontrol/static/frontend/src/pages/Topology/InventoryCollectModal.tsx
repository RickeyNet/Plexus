import { useState } from "react";

import { groupLabel } from "@/api/inventory";
import type { InventoryCollectRequest } from "@/api/meraki";
import {
  useCredentialsList,
  useServiceCredentialsList,
  type CredentialSummary,
} from "@/api/settings";
import { useInventoryGroupsLite } from "@/api/topology";
import { Modal } from "@/components/Modal";

import {
  defaultCollectCredential,
  SETTINGS_SERVICE_CREDENTIAL,
} from "./merakiHelpers";

interface Props {
  /** The inventory group selected on the map; null when the map shows every group. */
  groupId: number | null;
  /** The service credential Settings names, the default; null when Settings names none. */
  serviceCredentialId: number | null;
  /** An administrator sees every service credential, not only the one Settings names. */
  isAdmin: boolean;
  /** Starts the collection (and reports a failure to start). */
  onCollect: (body: InventoryCollectRequest) => void;
  isPending: boolean;
  onClose: () => void;
}

function credentialLabel(c: CredentialSummary): string {
  return c.username ? `${c.name} (${c.username})` : c.name;
}

/**
 * Asks which inventory devices to read and with which credential before an
 * inventory collection (route tables, running configurations, VLANs, ports,
 * CDP / LLDP neighbors and MAC tables over SSH).
 * The service credentials come first, the one Settings names preselected.
 */
export function InventoryCollectModal({
  groupId,
  serviceCredentialId,
  isAdmin,
  onCollect,
  isPending,
  onClose,
}: Props) {
  const groups = useInventoryGroupsLite();
  const serviceCredentials = useServiceCredentialsList(isAdmin);
  const ownCredentials = useCredentialsList();
  const [group, setGroup] = useState<string>(
    groupId != null ? String(groupId) : "",
  );
  const [picked, setPicked] = useState<string | null>(null);

  const serviceRows = isAdmin ? (serviceCredentials.data ?? []) : [];
  const ownRows = ownCredentials.data ?? [];
  const credential =
    picked ??
    defaultCollectCredential(
      serviceCredentialId,
      serviceRows.map((c) => c.id),
      ownRows.map((c) => c.id),
      isAdmin,
    );
  const loading =
    ownCredentials.isPending || (isAdmin && serviceCredentials.isPending);

  const handleCollect = () =>
    onCollect({
      group_id: group ? parseInt(group, 10) : null,
      credential_id:
        credential === SETTINGS_SERVICE_CREDENTIAL
          ? null
          : parseInt(credential, 10),
    });

  return (
    <Modal isOpen onClose={onClose} title="Collect from all other devices (SSH)">
      <p className="text-muted" style={{ marginTop: 0, fontSize: "0.9rem" }}>
        Opens one read-only SSH session per device and stores its route table
        and running configuration for the path trace, and its VLANs, ports, CDP
        / LLDP neighbors and MAC address table for the map. No SNMP is needed.
      </p>
      <div className="form-group">
        <label className="form-label" htmlFor="inventory-collect-group">
          Devices
        </label>
        <select
          id="inventory-collect-group"
          className="form-select"
          style={{ width: "100%" }}
          value={group}
          onChange={(e) => setGroup(e.target.value)}
        >
          <option value="">All inventory devices</option>
          {(groups.data ?? []).map((g) => (
            <option key={g.id} value={g.id}>
              {groupLabel(g)}
            </option>
          ))}
        </select>
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor="inventory-collect-credential">
          Credential
        </label>
        <select
          id="inventory-collect-credential"
          className="form-select"
          style={{ width: "100%" }}
          value={credential}
          onChange={(e) => setPicked(e.target.value)}
        >
          {/* A user who cannot list the service credentials still gets the one Settings names. */}
          {!isAdmin && serviceCredentialId != null && (
            <option value={SETTINGS_SERVICE_CREDENTIAL}>
              Plexus service credential (Settings)
            </option>
          )}
          {serviceRows.length > 0 && (
            <optgroup label="Service credentials">
              {serviceRows.map((c) => (
                <option key={c.id} value={c.id}>
                  {credentialLabel(c)}
                  {c.id === serviceCredentialId ? " — default in Settings" : ""}
                </option>
              ))}
            </optgroup>
          )}
          {ownRows.length > 0 && (
            <optgroup label="My credentials">
              {ownRows.map((c) => (
                <option key={c.id} value={c.id}>
                  {credentialLabel(c)}
                </option>
              ))}
            </optgroup>
          )}
        </select>
        {!credential && !loading && (
          <div
            className="text-muted"
            style={{ fontSize: "0.85em", marginTop: "0.35rem" }}
          >
            No credential to sign in with: add a service credential under
            Settings, or one of your own under Credentials.
          </div>
        )}
      </div>
      <div
        style={{ display: "flex", gap: "0.5rem", justifyContent: "flex-end" }}
      >
        <button
          type="button"
          className="btn btn-sm btn-secondary"
          onClick={onClose}
        >
          Cancel
        </button>
        <button
          type="button"
          className="btn btn-sm btn-primary"
          disabled={isPending || !credential}
          onClick={handleCollect}
        >
          {isPending ? "Starting…" : "Collect"}
        </button>
      </div>
    </Modal>
  );
}
