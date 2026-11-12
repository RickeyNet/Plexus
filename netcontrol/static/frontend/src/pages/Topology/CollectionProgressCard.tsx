import {
  type CollectionProgress,
  type TopologySource,
  type TopologySourceType,
  isCloudAccountProvider,
} from "@/api/meraki";
import { ProgressBar } from "@/components/ProgressBar";

import { PROVIDER_INVENTORY, providerLabel } from "./helpers";
import { describeProgress } from "./merakiHelpers";

/** What a collection from a source of this type costs, and when the map updates. */
function progressNote(type: TopologySourceType): string {
  if (type === "aws")
    return "An AWS account takes about a dozen requests per region; All regions reads every region the account has enabled. The map updates when discovery finishes.";
  if (isCloudAccountProvider(type))
    return "The map updates when discovery finishes.";
  const cost =
    type === PROVIDER_INVENTORY
      ? "One SSH session per device, a few at a time. The path trace uses the new route tables and configurations at the next trace."
      : type === "cato"
        ? "A Cato account takes a few queries, sent slowly to stay inside the Cato API rate limits."
        : type === "fmc"
          ? "An FMC takes several requests per device (interfaces, routing, NAT, policies), sent slowly to stay inside the FMC limit of 120 requests per minute."
          : type === "panorama"
            ? "A Panorama takes a few requests per device group and template, plus a few per firewall when device state is collected."
            : type === "appgate"
              ? "An Appgate collective takes one query per connected user for the access details; large user counts take a while."
              : "Large organizations take several minutes: Meraki limits the API to 10 requests per second.";
  return `${cost} You can close this dialog; the map updates when collection finishes.`;
}

/** The card's heading: what is being collected, from where. */
function progressTitle(
  source: Pick<TopologySource, "type" | "name">,
): string {
  if (source.type === PROVIDER_INVENTORY)
    return "Collecting from inventory devices…";
  const label = providerLabel(source.type);
  return isCloudAccountProvider(source.type)
    ? `Discovering ${source.name} (${label})…`
    : `Collecting from ${source.name} (${label})…`;
}

/** A running collection: what it is doing, a bar (full and dimmed when the total is unknown) and a note. */
export function CollectionProgressCard({
  source,
  progress,
}: {
  source: Pick<TopologySource, "type" | "name">;
  /** Missing while the collection has reported nothing yet. */
  progress: CollectionProgress | null | undefined;
}) {
  const title = progressTitle(source);
  const { label, percent } = describeProgress(
    { progress: progress ?? {} },
    source.type,
  );
  return (
    <div className="card" style={{ marginTop: "var(--space-4)" }}>
      <strong>{title}</strong>
      <div className="text-muted" style={{ margin: "0.35rem 0" }}>
        {label}
      </div>
      <ProgressBar value={percent} label={title} />
      <div
        className="text-muted"
        style={{ fontSize: "0.85em", marginTop: "0.35rem" }}
      >
        {progressNote(source.type)}
      </div>
    </div>
  );
}
