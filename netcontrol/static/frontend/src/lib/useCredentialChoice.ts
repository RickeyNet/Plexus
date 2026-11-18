import { useState } from "react";

import {
  useCredentialsList,
  useServiceCredentialsList,
  type CredentialSummary,
} from "@/api/settings";

import { defaultCollectCredential } from "./credentialChoice";

export interface CredentialChoice {
  /** The select value: a credential id, the Settings placeholder, or '' for none. */
  credential: string;
  setCredential: (value: string) => void;
  /** Service credentials (an administrator's list; empty for anyone else). */
  serviceRows: CredentialSummary[];
  /** The user's own credentials. */
  ownRows: CredentialSummary[];
  loading: boolean;
  /** True once the user picked a credential (false: the preselected default). */
  picked: boolean;
}

/**
 * The credential picker's state: `preferredId` when the user's list holds
 * it, else the service credential Settings names, is preselected (see
 * `defaultCollectCredential`) until the user picks another.
 */
export function useCredentialChoice(
  serviceCredentialId: number | null,
  isAdmin: boolean,
  preferredId?: number | null,
): CredentialChoice {
  const serviceCredentials = useServiceCredentialsList(isAdmin);
  const ownCredentials = useCredentialsList();
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
      preferredId,
    );
  return {
    credential,
    setCredential: setPicked,
    serviceRows,
    ownRows,
    loading:
      ownCredentials.isPending || (isAdmin && serviceCredentials.isPending),
    picked: picked != null,
  };
}
