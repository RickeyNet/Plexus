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
}

/**
 * The credential picker's state: the service credential Settings names is
 * preselected (see `defaultCollectCredential`) until the user picks another.
 */
export function useCredentialChoice(
  serviceCredentialId: number | null,
  isAdmin: boolean,
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
    );
  return {
    credential,
    setCredential: setPicked,
    serviceRows,
    ownRows,
    loading:
      ownCredentials.isPending || (isAdmin && serviceCredentials.isPending),
  };
}
