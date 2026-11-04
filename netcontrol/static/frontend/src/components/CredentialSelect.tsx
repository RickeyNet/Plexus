import { credentialLabel, SETTINGS_SERVICE_CREDENTIAL } from "@/lib/credentialChoice";
import type { CredentialChoice } from "@/lib/useCredentialChoice";

interface Props {
  id: string;
  choice: CredentialChoice;
  /** The service credential Settings names; null when Settings names none. */
  serviceCredentialId: number | null;
  isAdmin: boolean;
  disabled?: boolean;
}

/**
 * The credential an SSH read signs in with: service credentials first (the
 * one Settings names marked as the default), then the user's own.
 */
export function CredentialSelect({
  id,
  choice,
  serviceCredentialId,
  isAdmin,
  disabled,
}: Props) {
  const { credential, setCredential, serviceRows, ownRows, loading } = choice;
  return (
    <>
      <select
        id={id}
        className="form-select"
        style={{ width: "100%" }}
        value={credential}
        disabled={disabled}
        onChange={(e) => setCredential(e.target.value)}
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
    </>
  );
}
