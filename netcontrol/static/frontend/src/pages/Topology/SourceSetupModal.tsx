import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";

import {
  type MerakiOrg,
  type MerakiValidateResult,
  isInventoryCollectionResult,
  useMerakiBuildJob,
  useMerakiOrgs,
  useSourceSchedule,
  useStartMerakiBuild,
  useTopologySources,
  useUpdateSourceSchedule,
  useValidateMerakiOrg,
} from "@/api/meraki";
import { Badge } from "@/components/Badge";
import { Callout } from "@/components/Callout";
import { LoadingState } from "@/components/LoadingState";
import { Modal } from "@/components/Modal";

import { CollectionProgressCard } from "./CollectionProgressCard";
import { errorText } from "./helpers";
import { ImportDevicesStep } from "./ImportDevicesStep";
import { describeNextCollection } from "./merakiHelpers";
import { SETUP_STEPS, type SetupStep, stepState } from "./sourceSetup";

const STATE_LABEL = { done: "done", current: "now", todo: "next" } as const;
const STATE_TONE = { done: "success", current: "primary", todo: "neutral" } as const;

/** The step list at the top: each step's name with its state as text, not only colour. */
function StepList({ current }: { current: SetupStep }) {
  return (
    <ol
      style={{
        display: "flex",
        gap: "1rem",
        flexWrap: "wrap",
        listStyle: "none",
        padding: 0,
        margin: "0 0 1rem",
      }}
    >
      {SETUP_STEPS.map((step, i) => {
        const state = stepState(step.key, current);
        return (
          <li
            key={step.key}
            aria-current={state === "current" ? "step" : undefined}
            style={{ display: "flex", gap: "0.4rem", alignItems: "center" }}
          >
            <strong>
              {i + 1}. {step.label}
            </strong>
            <Badge size="sm" tone={STATE_TONE[state]}>
              {STATE_LABEL[state]}
            </Badge>
          </li>
        );
      })}
    </ol>
  );
}

/** Whether the source is collected on a schedule, with a one-click fix when the global schedule is off. */
function ScheduleNote({ org }: { org: MerakiOrg }) {
  const schedule = useSourceSchedule(true);
  const save = useUpdateSourceSchedule();
  const orgs = useMerakiOrgs();
  const [error, setError] = useState<string | null>(null);
  const current = orgs.data?.orgs.find((o) => o.id === org.id) ?? org;
  const enabled = schedule.data?.config.enabled;
  if (enabled === undefined) return null;
  if (!current.auto_collect) {
    return (
      <p className="text-muted" style={{ fontSize: "0.9em" }}>
        Scheduled collection is turned off for this source (its Edit form):
        collect it with Collect Now when you want a fresh picture.
      </p>
    );
  }
  if (!enabled) {
    return (
      <Callout
        tone="warning"
        title="Scheduled collection is off"
        action={
          <button
            type="button"
            className="btn btn-sm btn-primary"
            disabled={save.isPending}
            onClick={() => {
              setError(null);
              save
                .mutateAsync({ enabled: true })
                .catch((err) => setError(errorText(err)));
            }}
          >
            {save.isPending ? "Turning on…" : "Turn on"}
          </button>
        }
      >
        No source is collected on its own, so this map goes stale. Turn on
        scheduled collection to collect every source once an hour (the
        interval can be changed under Map Sources).
        {error && <div>Could not turn it on: {error}</div>}
      </Callout>
    );
  }
  const next = describeNextCollection(current.next_collection_at);
  return (
    <p className="text-muted" style={{ fontSize: "0.9em" }}>
      Scheduled collection is on{next ? `; next collection: ${next}` : ""}.
    </p>
  );
}

export interface SourceSetupModalProps {
  /** The source just added (or just edited after a failed check). */
  org: MerakiOrg;
  /** Back to the source's form to fix what failed; the source stays saved. */
  onEdit: () => void;
  onClose: () => void;
}

/**
 * What follows adding a source: check its credentials, run its first
 * collection, then offer to import the devices it found. Every step can be
 * left with Close: the source stays saved and a running collection goes on.
 */
export function SourceSetupModal({ org, onEdit, onClose }: SourceSetupModalProps) {
  const qc = useQueryClient();
  const validate = useValidateMerakiOrg();
  const startBuild = useStartMerakiBuild();
  const [phase, setPhase] = useState<"credentials" | "collecting">("credentials");
  const [check, setCheck] = useState<MerakiValidateResult | null>(null);
  const [checkError, setCheckError] = useState<string | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [startError, setStartError] = useState<string | null>(null);
  // A collection was already running (the scheduler takes a new source at
  // its next pass): follow it through the sources list instead.
  const [following, setFollowing] = useState(false);
  const job = useMerakiBuildJob(jobId);
  const sources = useTopologySources(following);
  const followed = following
    ? sources.data?.sources.find((s) => s.type === org.provider && s.id === org.id)
    : undefined;

  const collect = () => {
    setPhase("collecting");
    setStartError(null);
    setFollowing(false);
    setJobId(null);
    startBuild.mutate(org.id, {
      onSuccess: (started) => setJobId(started.job_id),
      onError: (err) => {
        if (/already running/i.test(errorText(err))) {
          setFollowing(true);
          qc.invalidateQueries({ queryKey: ["meraki", "sources"] });
        } else setStartError(errorText(err));
      },
    });
  };

  const runCheck = () => {
    setCheck(null);
    setCheckError(null);
    validate.mutate(org.id, {
      onSuccess: (result) => {
        setCheck(result);
        if (result.ok) collect();
      },
      onError: (err) => setCheckError(errorText(err)),
    });
  };

  // The check starts on its own when the dialog opens (once, even under StrictMode).
  const started = useRef(false);
  useEffect(() => {
    if (started.current) return;
    started.current = true;
    runCheck();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // "never" is a list read before the running collection showed up in it.
  const followedStatus =
    followed && !followed.collecting && followed.status !== "never" ? followed.status : undefined;
  const jobStatus = following
    ? followedStatus === "success"
      ? "completed"
      : followedStatus
    : job.data?.status;
  const settled = following
    ? followedStatus !== undefined
    : jobId !== null && (job.isError || (jobStatus !== undefined && jobStatus !== "running"));
  const collected = settled && (jobStatus === "completed" || jobStatus === "partial");
  // A finished collection is new map data.
  useEffect(() => {
    if (!settled) return;
    qc.invalidateQueries({ queryKey: ["meraki"] });
    qc.invalidateQueries({ queryKey: ["topology"] });
  }, [settled, qc]);

  const step: SetupStep = phase === "credentials" ? "credentials" : collected ? "import" : "collecting";
  const result = following ? null : job.data?.result;
  const summary = result && !isInventoryCollectionResult(result) ? result.summary : null;
  const failureMessage = following ? followed?.message : job.data?.error;
  const collectFailure =
    startError ??
    (settled && !collected
      ? failureMessage || "Lost track of the collection; check Map Sources for its result."
      : null);

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={`Set up ${org.name}`}
      size="large"
      footer={
        <button type="button" className="btn btn-secondary" onClick={onClose}>
          {step === "import" ? "Done" : "Close"}
        </button>
      }
    >
      <StepList current={step} />

      {step === "credentials" && (
        <>
          {(validate.isPending || (!check && !checkError)) && (
            <LoadingState text="Checking the credentials…" />
          )}
          {(checkError || (check && !check.ok)) && (
            <Callout
              tone="danger"
              title="The credentials did not work"
              action={
                <div style={{ display: "flex", gap: "0.4rem" }}>
                  <button type="button" className="btn btn-sm btn-primary" onClick={onEdit}>
                    Edit source
                  </button>
                  <button
                    type="button"
                    className="btn btn-sm btn-secondary"
                    disabled={validate.isPending}
                    onClick={runCheck}
                  >
                    Check again
                  </button>
                </div>
              }
            >
              {checkError ?? check?.message}
              <div style={{ marginTop: "0.35rem" }}>
                The source is saved. Fix its fields with Edit source, or close
                this dialog and come back to it under Map Sources.
              </div>
            </Callout>
          )}
        </>
      )}

      {step !== "credentials" && check?.ok && (
        <Callout tone="success">Credentials checked: {check.message}</Callout>
      )}

      {step === "collecting" && (
        <>
          {!collectFailure && (
            <CollectionProgressCard
              source={{ type: org.provider, name: org.name }}
              progress={following ? followed?.progress : job.data?.progress}
            />
          )}
          {collectFailure && (
            <Callout
              tone="danger"
              title="The first collection failed"
              action={
                <div style={{ display: "flex", gap: "0.4rem" }}>
                  <button
                    type="button"
                    className="btn btn-sm btn-primary"
                    disabled={startBuild.isPending}
                    onClick={collect}
                  >
                    Retry
                  </button>
                  <button type="button" className="btn btn-sm btn-secondary" onClick={onEdit}>
                    Edit source
                  </button>
                </div>
              }
            >
              {collectFailure}
            </Callout>
          )}
        </>
      )}

      {step === "import" && (
        <>
          <Callout tone="success">
            First collection done
            {summary
              ? `: ${summary.sites ?? 0} sites, ${summary.devices ?? 0} devices`
              : followed?.detail
                ? `: ${followed.detail}`
                : ""}
            {jobStatus === "partial" ? " (with warnings; see Map Sources)" : ""}.
          </Callout>
          <ScheduleNote org={org} />
          <ImportDevicesStep orgRef={org.id} onNavigate={onClose} />
        </>
      )}
    </Modal>
  );
}
