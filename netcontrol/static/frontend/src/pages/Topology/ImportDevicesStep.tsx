import { useId, useMemo, useState } from "react";
import { Link } from "react-router";

import { useConfigBackupPolicies } from "@/api/configuration";
import { useSnmpProfiles } from "@/api/inventory";
import { useTopologySources } from "@/api/meraki";
import {
  type ImportableDevice,
  type ImportDevicesResult,
  useImportableDevices,
  useImportSourceDevices,
} from "@/api/sourceImport";
import {
  useInventoryGroupsList,
  useMonitoringConfig,
  useUpdateMonitoringConfig,
} from "@/api/settings";
import { Badge } from "@/components/Badge";
import { Callout } from "@/components/Callout";
import { CredentialSelect } from "@/components/CredentialSelect";
import { LoadingState } from "@/components/LoadingState";
import { QueryError } from "@/components/QueryError";
import { ShowMoreButton } from "@/components/ShowMoreButton";
import { credentialIdFromChoice } from "@/lib/credentialChoice";
import { DEVICE_TYPES } from "@/lib/deviceTypes";
import { useCredentialChoice } from "@/lib/useCredentialChoice";
import { useShowMore } from "@/lib/useShowMore";
import { SETUP_LINKS } from "@/pages/Dashboard/setupGuide";

import { errorText } from "./helpers";
import {
  backupCapableCount,
  buildImportRequest,
  capabilityText,
  defaultSelection,
  describeImportResult,
  filterDevices,
  importBlocker,
  type ImportTarget,
  snmpCapableCount,
  soleProfileId,
  toggleDevice,
} from "./sourceSetup";

const NOTE = { fontSize: "0.85em", marginTop: "0.35rem" } as const;
const BACKUPS_PATH = "/configuration/backups";
const INVENTORY_PATH = "/inventory";

function deviceTypeLabel(value: string): string {
  return DEVICE_TYPES.find((t) => t.value === value)?.label ?? value;
}

/** Monitoring's global switch: imported hosts are pinged and polled only while it is on. */
function MonitoringNote({ enabledAtLoad }: { enabledAtLoad: boolean }) {
  const config = useMonitoringConfig();
  const save = useUpdateMonitoringConfig();
  const [error, setError] = useState<string | null>(null);
  const enabled = config.data?.enabled ?? enabledAtLoad;
  if (enabled) {
    return (
      <p className="text-muted" style={NOTE}>
        Monitoring is on: every inventory host is pinged, and the hosts of a
        group with an SNMP profile are also polled over SNMP. There is nothing
        else to switch on per device.
      </p>
    );
  }
  return (
    <Callout
      tone="warning"
      title="Monitoring is off"
      action={
        config.data && (
          <button
            type="button"
            className="btn btn-sm btn-primary"
            disabled={save.isPending}
            onClick={() => {
              setError(null);
              if (config.data)
                save
                  .mutateAsync({ ...config.data, enabled: true })
                  .catch((err) => setError(errorText(err)));
            }}
          >
            {save.isPending ? "Turning on…" : "Turn on monitoring"}
          </button>
        )
      }
    >
      Imported devices are not pinged or polled until monitoring is turned on
      (Settings › Monitoring, every {Math.round((config.data?.interval_seconds ?? 300) / 60)} minutes).
      {error && <div>Could not turn it on: {error}</div>}
    </Callout>
  );
}

function DeviceRow({
  device,
  checked,
  disabled,
  onToggle,
}: {
  device: ImportableDevice;
  checked: boolean;
  disabled: boolean;
  onToggle: () => void;
}) {
  return (
    <tr>
      <td>
        <input
          type="checkbox"
          aria-label={`Import ${device.name}`}
          checked={checked}
          disabled={disabled}
          onChange={onToggle}
        />
      </td>
      <td>
        {device.name}
        {device.site && (
          <div className="text-muted" style={{ fontSize: "0.85em" }}>
            {device.site}
          </div>
        )}
      </td>
      <td>{device.ip}</td>
      <td>{device.model}</td>
      <td>
        {device.existing ? (
          <Badge size="sm" tone="neutral" title={`Inventory host ${device.existing.hostname}`}>
            In inventory{device.existing.group_name ? `: ${device.existing.group_name}` : ""}
          </Badge>
        ) : (
          deviceTypeLabel(device.device_type)
        )}
      </td>
      <td>{capabilityText(device)}</td>
    </tr>
  );
}

function ImportOutcome({ result, onNavigate }: { result: ImportDevicesResult; onNavigate: () => void }) {
  const failed = [...result.errors.map((e) => `${e.hostname} (${e.ip_address}): ${e.error}`)];
  return (
    <Callout tone={result.counts.errors ? "warning" : "success"} title="Import finished">
      <ul style={{ margin: "0.25rem 0 0", paddingLeft: "1.2rem" }}>
        {describeImportResult(result).map((line) => (
          <li key={line}>{line}</li>
        ))}
        {failed.map((line) => (
          <li key={line}>{line}</li>
        ))}
      </ul>
      <Link to={INVENTORY_PATH} onClick={onNavigate}>
        Open the inventory
      </Link>
    </Callout>
  );
}

export interface ImportDevicesStepProps {
  orgRef: number;
  /** Called when a link leaves the Topology page. */
  onNavigate: () => void;
}

/**
 * The last setup step: pick devices of the source's latest collection, the
 * group they go into, an SNMP profile and a backup policy, then import.
 * Nothing happens until Import is clicked.
 */
export function ImportDevicesStep({ orgRef, onNavigate }: ImportDevicesStepProps) {
  const uid = useId();
  const importable = useImportableDevices(orgRef);
  const profiles = useSnmpProfiles();
  const groups = useInventoryGroupsList();
  const policies = useConfigBackupPolicies();
  const sources = useTopologySources();
  const run = useImportSourceDevices();

  const devices = useMemo(() => importable.data?.devices ?? [], [importable.data]);
  const max = importable.data?.max_devices ?? 500;
  const [picked, setPicked] = useState<Set<string> | null>(null);
  const selected = picked ?? defaultSelection(devices, max);
  const [query, setQuery] = useState("");
  const [targetMode, setTargetMode] = useState<"new" | "existing">("new");
  const [groupName, setGroupName] = useState<string | null>(null);
  const [groupId, setGroupId] = useState<number | null>(null);
  const [profileChoice, setProfileChoice] = useState<string | null>(null);
  const [wantBackup, setWantBackup] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ImportDevicesResult | null>(null);

  const serviceCredentialId =
    sources.data?.sources.find((s) => s.type === "inventory")?.service_credential_id ?? null;
  const credentialChoice = useCredentialChoice(serviceCredentialId, true);

  const shown = filterDevices(devices, query);
  const { visible, hiddenCount, showMore } = useShowMore(shown);

  if (importable.error && !importable.data) return <QueryError what="the devices of this source" query={importable} />;
  if (!importable.data) return <LoadingState text="Reading the devices it found…" />;
  const data = importable.data;

  if (result) return <ImportOutcome result={result} onNavigate={onNavigate} />;

  if (devices.length === 0) {
    return (
      <Callout tone="info" title="No devices to import">
        {data.reason}
        {data.provider_note && <div style={NOTE}>{data.provider_note}</div>}
      </Callout>
    );
  }

  const profileList = profiles.data ?? [];
  const profileId = profileChoice ?? soleProfileId(profileList);
  const target: ImportTarget =
    targetMode === "new"
      ? { mode: "new", name: groupName ?? data.suggested_group_name }
      : { mode: "existing", groupId };
  const snmpCount = snmpCapableCount(devices, selected);
  const backupCount = backupCapableCount(devices, selected);
  const groupPolicy =
    target.mode === "existing" ? (policies.data ?? []).find((p) => p.group_id === target.groupId) : undefined;
  const backupCredentialId = credentialIdFromChoice(credentialChoice.credential);
  const offerBackup = backupCount > 0 && !groupPolicy;
  const choices = {
    target,
    profileId: snmpCount > 0 ? profileId : "",
    backupCredentialId: offerBackup && wantBackup ? backupCredentialId : null,
  };
  const blocker =
    importBlocker(selected.size, choices) ??
    (offerBackup && wantBackup && backupCredentialId == null
      ? "Choose a credential for the backups, or untick the backup."
      : null);
  const already = devices.filter((d) => d.existing).length;

  const submit = async () => {
    setError(null);
    try {
      setResult(await run.mutateAsync({ orgRef, body: buildImportRequest(devices, selected, choices) }));
    } catch (err) {
      setError(errorText(err));
    }
  };

  return (
    <div className="stack stack-sm">
      <h4 style={{ margin: "0.5rem 0 0" }}>Import the devices it found into the inventory</h4>
      <p className="text-muted" style={{ margin: 0, fontSize: "0.9em" }}>
        Optional: you can close this dialog and do it later. {data.provider_note}
      </p>

      <div className="toolbar" style={{ gap: "0.5rem", flexWrap: "wrap" }}>
        <input
          className="form-input"
          type="search"
          placeholder="Filter by name, address, model, site"
          aria-label="Filter devices"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          style={{ maxWidth: "20rem" }}
        />
        <button
          type="button"
          className="btn btn-sm btn-secondary"
          onClick={() => setPicked(defaultSelection(devices, max))}
        >
          Select all new
        </button>
        <button type="button" className="btn btn-sm btn-secondary" onClick={() => setPicked(new Set())}>
          Select none
        </button>
        <span className="text-muted" style={{ fontSize: "0.9em" }}>
          {selected.size} of {devices.length} selected
          {already ? `, ${already} already in the inventory` : ""}
          {devices.length - already > max ? ` (one import takes at most ${max})` : ""}
        </span>
      </div>

      <div style={{ maxHeight: "22rem", overflowY: "auto" }}>
        <table className="data-table">
          <thead>
            <tr>
              <th aria-label="Import" />
              <th>Device</th>
              <th>Address</th>
              <th>Model</th>
              <th>Device type</th>
              <th>Plexus will</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((device) => (
              <DeviceRow
                key={device.key}
                device={device}
                checked={selected.has(device.key)}
                disabled={Boolean(device.existing) || (!selected.has(device.key) && selected.size >= max)}
                onToggle={() => setPicked(toggleDevice(selected, device, max))}
              />
            ))}
          </tbody>
        </table>
        <ShowMoreButton hiddenCount={hiddenCount} onClick={showMore} style={{ marginTop: "0.5rem" }} />
      </div>

      <fieldset className="form-group" style={{ border: "none", padding: 0, margin: 0 }}>
        <legend className="form-label">Inventory group</legend>
        <label style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
          <input
            type="radio"
            name={`${uid}-target`}
            checked={targetMode === "new"}
            onChange={() => setTargetMode("new")}
          />
          New group
          <input
            className="form-input"
            aria-label="New group name"
            value={target.mode === "new" ? target.name : (groupName ?? data.suggested_group_name)}
            disabled={targetMode !== "new"}
            maxLength={120}
            onChange={(e) => setGroupName(e.target.value)}
            style={{ maxWidth: "20rem" }}
          />
        </label>
        <label style={{ display: "flex", gap: "0.5rem", alignItems: "center", marginTop: "0.35rem" }}>
          <input
            type="radio"
            name={`${uid}-target`}
            checked={targetMode === "existing"}
            disabled={(groups.data ?? []).length === 0}
            onChange={() => setTargetMode("existing")}
          />
          Existing group
          <select
            className="form-select"
            aria-label="Existing group"
            value={groupId ?? ""}
            disabled={targetMode !== "existing"}
            onChange={(e) => setGroupId(e.target.value ? Number(e.target.value) : null)}
            style={{ maxWidth: "20rem" }}
          >
            <option value="">Choose a group…</option>
            {(groups.data ?? []).map((g) => (
              <option key={g.id} value={g.id}>
                {g.name}
              </option>
            ))}
          </select>
        </label>
      </fieldset>

      <div className="form-group">
        <label className="form-label" htmlFor={`${uid}-profile`}>
          SNMP profile
        </label>
        {snmpCount === 0 ? (
          <div className="text-muted" style={NOTE}>
            None of the selected devices can be polled over SNMP: Plexus pings them.
          </div>
        ) : profileList.length === 0 && profiles.isSuccess ? (
          <div className="text-muted" style={NOTE}>
            No SNMP profile exists yet, so the devices are only pinged for now.{" "}
            <Link to={SETUP_LINKS.snmpProfiles} onClick={onNavigate}>
              Create an SNMP profile
            </Link>{" "}
            and assign it to the group to poll them over SNMP.
          </div>
        ) : (
          <>
            <select
              id={`${uid}-profile`}
              className="form-select"
              value={profileId}
              onChange={(e) => setProfileChoice(e.target.value)}
              style={{ maxWidth: "20rem" }}
            >
              <option value="">No profile (ping only)</option>
              {profileList.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                  {p.enabled ? "" : " (SNMP off in this profile)"}
                </option>
              ))}
            </select>
            <div className="text-muted" style={NOTE}>
              The profile is assigned to the group: {snmpCount} of the selected
              devices are polled over SNMP with it (a group that already has a
              profile keeps its own).
            </div>
          </>
        )}
      </div>

      <div className="form-group">
        <div className="form-label">Configuration backups</div>
        {backupCount === 0 ? (
          <div className="text-muted" style={NOTE}>
            Config Backups cannot read the configuration of any selected device
            (cloud-managed devices, and firewalls whose configuration lives in
            their manager), so no backup policy is offered.{" "}
            <Link to={BACKUPS_PATH} onClick={onNavigate}>
              Config Backups
            </Link>
          </div>
        ) : groupPolicy ? (
          <div className="text-muted" style={NOTE}>
            The group&apos;s backup policy &quot;{groupPolicy.name}&quot; will back
            them up too.
          </div>
        ) : (
          <>
            <label style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
              <input type="checkbox" checked={wantBackup} onChange={(e) => setWantBackup(e.target.checked)} />
              Back up the configuration of {backupCount} device{backupCount === 1 ? "" : "s"} daily
              (a new policy for the group, backups kept 30 days), signing in with:
            </label>
            {wantBackup && (
              <div style={{ maxWidth: "24rem", marginTop: "0.35rem" }}>
                <CredentialSelect
                  id={`${uid}-credential`}
                  choice={credentialChoice}
                  serviceCredentialId={serviceCredentialId}
                  isAdmin
                />
              </div>
            )}
          </>
        )}
      </div>

      <MonitoringNote enabledAtLoad={data.monitoring_enabled} />

      {error && <Callout tone="danger">Import failed: {error}</Callout>}
      <div style={{ display: "flex", gap: "0.75rem", alignItems: "center" }}>
        <button
          type="button"
          className="btn btn-primary"
          disabled={Boolean(blocker) || run.isPending}
          onClick={() => void submit()}
        >
          {run.isPending ? "Importing…" : `Import ${selected.size} device${selected.size === 1 ? "" : "s"}`}
        </button>
        {blocker && <span className="text-muted">{blocker}</span>}
      </div>
    </div>
  );
}
