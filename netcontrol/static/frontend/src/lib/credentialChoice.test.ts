import { describe, expect, it } from "vitest";

import {
  credentialIdFromChoice,
  credentialLabel,
  defaultCollectCredential,
  SETTINGS_SERVICE_CREDENTIAL,
} from "./credentialChoice";

describe("credential choice", () => {
  it("preselects the service credential Settings names", () => {
    expect(defaultCollectCredential(4, [4, 7], [12], true)).toBe("4");
    expect(defaultCollectCredential(4, [], [12], false)).toBe(
      SETTINGS_SERVICE_CREDENTIAL,
    );
    expect(defaultCollectCredential(null, [], [], false)).toBe("");
  });

  it("preselects the group's remembered credential when the user's list holds it", () => {
    // An administrator's service list, or anyone's own credentials.
    expect(defaultCollectCredential(4, [4, 7], [12], true, 7)).toBe("7");
    expect(defaultCollectCredential(4, [], [12], false, 12)).toBe("12");
    // Not in the list (another user's, or a service credential a
    // non-administrator cannot list): the usual default.
    expect(defaultCollectCredential(4, [], [12], false, 7)).toBe(
      SETTINGS_SERVICE_CREDENTIAL,
    );
    expect(defaultCollectCredential(4, [4, 7], [12], true, 99)).toBe("4");
    expect(defaultCollectCredential(4, [4, 7], [12], true, null)).toBe("4");
  });

  it("sends null for the Settings service credential and for no choice", () => {
    expect(credentialIdFromChoice(SETTINGS_SERVICE_CREDENTIAL)).toBeNull();
    expect(credentialIdFromChoice("")).toBeNull();
    expect(credentialIdFromChoice("12")).toBe(12);
    expect(credentialIdFromChoice("not-a-number")).toBeNull();
  });

  it("labels a credential with its username when it has one", () => {
    expect(credentialLabel({ name: "svc", username: "plexus" })).toBe(
      "svc (plexus)",
    );
    expect(credentialLabel({ name: "svc" })).toBe("svc");
  });
});
