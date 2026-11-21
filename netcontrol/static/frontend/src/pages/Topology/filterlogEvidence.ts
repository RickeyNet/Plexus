/**
 * Pure helpers of the OPNsense firewall log evidence: the pass / block
 * counts the firewall's filterlog lines give each rule (Rules tab) and a
 * path trace hop through the firewall.
 */
import type {
  OpnsenseLogEvidence,
  OpnsenseLogEvidenceInfo,
  OpnsenseLogFlow,
  PathLogEvidence,
} from "@/api/opnsenseRules";
import { formatCount } from "@/lib/formatCount";
import { formatRelativeTime } from "@/lib/datetime";
import type { Tone } from "@/lib/severity";

/** "12 passed, 3 blocked": the counts that are not zero ('' when both are). */
export function passBlockText(passes: number, blocks: number): string {
  const parts: string[] = [];
  if (passes) parts.push(`${formatCount(passes)} passed`);
  if (blocks) parts.push(`${formatCount(blocks)} blocked`);
  return parts.join(", ");
}

/** A rule's evidence in one line: the window, the last hour and when it was last logged. */
export function evidenceText(
  evidence: OpnsenseLogEvidence,
  info: Pick<OpnsenseLogEvidenceInfo, "window_hours" | "recent_hours">,
  now: number = Date.now(),
): string {
  const window = passBlockText(evidence.passes, evidence.blocks) || "none";
  const recent =
    passBlockText(evidence.passes_recent, evidence.blocks_recent) || "none";
  const last = formatRelativeTime(evidence.last_seen || null, now, "never");
  return `${info.window_hours} h: ${window} · last ${info.recent_hours} h: ${recent} · last logged ${last}`;
}

/** The tone of a rule's evidence: blocks show as danger, passes only as success. */
export function evidenceTone(
  evidence: Pick<OpnsenseLogEvidence, "passes" | "blocks">,
): Tone {
  if (evidence.blocks) return "danger";
  return evidence.passes ? "success" : "neutral";
}

/** One logged flow: "pass 192.0.2.10 → 192.0.2.140 tcp/443 ×4". */
export function flowText(flow: OpnsenseLogFlow): string {
  const port = flow.destination_port != null ? `/${flow.destination_port}` : "";
  return `${flow.action} ${flow.source} → ${flow.destination} ${flow.protocol}${port} ×${formatCount(flow.hits)}`;
}

/**
 * What the Rules tab says about the evidence as a whole: why there is none,
 * or when it was last received.
 */
export function evidenceStatus(
  info: OpnsenseLogEvidenceInfo | undefined,
  now: number = Date.now(),
): string {
  if (!info) return "";
  if (!info.enabled) {
    return "Firewall log evidence is off in Settings › Event receivers: log lines are dropped.";
  }
  if (!info.received_at) {
    return (
      "No firewall log received from this firewall. To see live passes and blocks per rule, send its firewall " +
      "log to the Plexus syslog receiver (on OPNsense: System › Settings › Logging, Remote, a destination with " +
      "the firewall log application or all applications) and turn " +
      'on "Log packets that are handled by this rule" on the rules to watch: only logged rules produce lines.'
    );
  }
  return `Firewall log last received ${formatRelativeTime(info.received_at, now, "never")}.`;
}

export interface EvidenceLine {
  text: string;
  tone: Tone;
}

/** The lines a path trace hop shows for its firewall log evidence. */
export function hopEvidenceLines(
  evidence: PathLogEvidence,
  now: number = Date.now(),
): EvidenceLine[] {
  const lines: EvidenceLine[] = [];
  for (const rule of evidence.rules) {
    const name = `Rule ${rule.number}${rule.description ? ` (${rule.description})` : ""}`;
    const counts = passBlockText(rule.passes, rule.blocks);
    if (counts) {
      const last = formatRelativeTime(rule.last_seen || null, now, "never");
      lines.push({
        text: `${name}: ${counts} in ${evidence.window_hours} h, last ${last}.`,
        tone: "neutral",
      });
    } else if (!rule.logs_packets) {
      lines.push({
        text: `${name}: no log lines; the rule does not log packets.`,
        tone: "neutral",
      });
    } else {
      lines.push({
        text: `${name}: not logged in ${evidence.window_hours} h.`,
        tone: "neutral",
      });
    }
  }
  const flow = evidence.flow;
  if (flow) {
    if (flow.matched) {
      const by = flow.rules.length ? ` by ${flow.rules.join("; ")}` : "";
      const last = formatRelativeTime(flow.last_seen || null, now, "never");
      lines.push({
        text: `This flow was logged: ${passBlockText(flow.passes, flow.blocks)}${by}, last ${last}.`,
        tone: evidence.contradiction ? "warning" : "neutral",
      });
    } else {
      lines.push({
        text: `This flow was not logged in ${evidence.window_hours} h.`,
        tone: "neutral",
      });
    }
  }
  if (evidence.contradiction)
    lines.push({ text: evidence.contradiction, tone: "danger" });
  return lines;
}
