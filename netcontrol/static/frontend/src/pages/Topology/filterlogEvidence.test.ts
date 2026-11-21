import { describe, expect, it } from "vitest";

import type {
  OpnsenseLogEvidence,
  OpnsenseLogEvidenceInfo,
  PathLogEvidence,
} from "@/api/opnsenseRules";

import {
  evidenceStatus,
  evidenceText,
  evidenceTone,
  flowText,
  hopEvidenceLines,
  passBlockText,
} from "./filterlogEvidence";

const NOW = Date.parse("2026-11-20T12:00:00Z");

function evidence(
  over: Partial<OpnsenseLogEvidence> = {},
): OpnsenseLogEvidence {
  return {
    rule_key: "11111111-1111-4111-8111-000000000001",
    passes: 1200,
    blocks: 0,
    passes_recent: 40,
    blocks_recent: 0,
    last_seen: "2026-11-20 11:55:00",
    seen_on: ["igb1 in"],
    flows: [],
    ...over,
  };
}

function info(
  over: Partial<OpnsenseLogEvidenceInfo> = {},
): OpnsenseLogEvidenceInfo {
  return {
    enabled: true,
    received_at: "2026-11-20 11:59:00",
    window_hours: 24,
    recent_hours: 1,
    bucket_seconds: 600,
    unmatched: [],
    ...over,
  };
}

describe("passBlockText", () => {
  it("names the counts that are not zero", () => {
    expect(passBlockText(1200, 3)).toBe("1,200 passed, 3 blocked");
    expect(passBlockText(0, 3)).toBe("3 blocked");
    expect(passBlockText(0, 0)).toBe("");
  });
});

describe("evidenceText and evidenceTone", () => {
  it("gives the window, the last hour and when it was last logged", () => {
    expect(evidenceText(evidence(), info(), NOW)).toBe(
      "24 h: 1,200 passed · last 1 h: 40 passed · last logged 5m ago",
    );
    expect(
      evidenceText(evidence({ passes_recent: 0, last_seen: "" }), info(), NOW),
    ).toContain("last 1 h: none · last logged never");
  });

  it("shows blocks as danger and passes only as success", () => {
    expect(evidenceTone(evidence())).toBe("success");
    expect(evidenceTone(evidence({ blocks: 1 }))).toBe("danger");
    expect(evidenceTone(evidence({ passes: 0 }))).toBe("neutral");
  });
});

describe("flowText", () => {
  it("writes a flow with its port when it has one", () => {
    const flow = {
      action: "block",
      source: "192.0.2.10",
      destination: "198.51.100.5",
      protocol: "tcp",
      destination_port: 443,
      hits: 4,
      last_seen: "2026-11-20 11:55:00",
    };
    expect(flowText(flow)).toBe("block 192.0.2.10 → 198.51.100.5 tcp/443 ×4");
    expect(
      flowText({ ...flow, protocol: "icmp", destination_port: null }),
    ).toBe("block 192.0.2.10 → 198.51.100.5 icmp ×4");
  });
});

describe("evidenceStatus", () => {
  it("explains why there is no evidence", () => {
    expect(evidenceStatus(undefined)).toBe("");
    expect(evidenceStatus(info({ enabled: false }))).toContain(
      "off in Settings",
    );
    const empty = evidenceStatus(info({ received_at: null }));
    expect(empty).toContain("syslog receiver");
    expect(empty).toContain("only logged rules produce lines");
    expect(evidenceStatus(info(), NOW)).toBe(
      "Firewall log last received 1m ago.",
    );
  });
});

describe("hopEvidenceLines", () => {
  const base: PathLogEvidence = {
    window_hours: 24,
    trace_says: "allowed",
    rules: [
      {
        number: 4,
        description: "Users to DMZ web",
        rule_key: "abc",
        logs_packets: true,
        passes: 3,
        blocks: 0,
        last_seen: "2026-11-20 11:00:00",
      },
      {
        number: 5,
        description: "",
        rule_key: "def",
        logs_packets: false,
        passes: 0,
        blocks: 0,
        last_seen: "",
      },
      {
        number: 6,
        description: "Logged",
        rule_key: "ghi",
        logs_packets: true,
        passes: 0,
        blocks: 0,
        last_seen: "",
      },
    ],
    flow: { matched: false, passes: 0, blocks: 0, last_seen: "", rules: [] },
    contradiction: "",
  };

  it("says what the log shows of each named rule and of the flow", () => {
    expect(hopEvidenceLines(base, NOW).map((l) => l.text)).toEqual([
      "Rule 4 (Users to DMZ web): 3 passed in 24 h, last 1h ago.",
      "Rule 5: no log lines; the rule does not log packets.",
      "Rule 6 (Logged): not logged in 24 h.",
      "This flow was not logged in 24 h.",
    ]);
  });

  it("spells out a contradiction plainly", () => {
    const lines = hopEvidenceLines(
      {
        ...base,
        rules: [],
        flow: {
          matched: true,
          passes: 0,
          blocks: 5,
          last_seen: "2026-11-20 11:58:00",
          rules: ["rule 2"],
        },
        contradiction:
          "The trace allows this flow here, but the firewall log shows it blocked 5 times.",
      },
      NOW,
    );
    expect(lines).toEqual([
      {
        text: "This flow was logged: 5 blocked by rule 2, last 2m ago.",
        tone: "warning",
      },
      {
        text: "The trace allows this flow here, but the firewall log shows it blocked 5 times.",
        tone: "danger",
      },
    ]);
  });

  it("leaves the flow out when the trace ends are no addresses", () => {
    expect(hopEvidenceLines({ ...base, rules: [], flow: null })).toEqual([]);
  });
});
