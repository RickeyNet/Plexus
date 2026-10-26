import { useState } from "react";

import { useSourceSchedule, useUpdateSourceSchedule } from "@/api/meraki";
import { useDialogs } from "@/components/DialogProvider-context";

/**
 * The schedule that collects every Meraki, Cato, Cisco FMC, Palo Alto
 * Panorama and Appgate SDP source on its own (administrators only). Each
 * source can opt out or set its own interval in its edit form.
 */
export function SourceScheduleBar() {
  const { alert } = useDialogs();
  const schedule = useSourceSchedule(true);
  const save = useUpdateSourceSchedule();
  const config = schedule.data?.config ?? null;
  const minMinutes = Math.round(
    (schedule.data?.min_interval_seconds ?? 300) / 60,
  );
  const maxMinutes = Math.round(
    (schedule.data?.max_interval_seconds ?? 86400) / 60,
  );

  const [enabled, setEnabled] = useState(true);
  const [minutes, setMinutes] = useState(60);
  const [prevConfig, setPrevConfig] = useState(config);
  // Re-seed the editable fields when the stored schedule loads or changes.
  if (config !== prevConfig) {
    setPrevConfig(config);
    setEnabled(Boolean(config?.enabled));
    setMinutes(Math.round((config?.interval_seconds ?? 3600) / 60));
  }

  const dirty =
    config !== null &&
    (enabled !== config.enabled || minutes * 60 !== config.interval_seconds);

  const handleSave = async () => {
    try {
      await save.mutateAsync({ enabled, interval_seconds: minutes * 60 });
    } catch (err) {
      void alert({
        message: `Could not save the schedule: ${err instanceof Error ? err.message : String(err)}`,
        variant: "error",
      });
    }
  };

  if (schedule.error) {
    return (
      <div className="error" style={{ marginBottom: "0.75rem" }}>
        <strong>Failed to load the collection schedule:</strong>{" "}
        {schedule.error.message}
      </div>
    );
  }

  return (
    <div
      className="card"
      style={{ padding: "0.75rem 1rem", marginBottom: "0.75rem" }}
    >
      <div
        style={{
          display: "flex",
          gap: "1rem",
          alignItems: "center",
          flexWrap: "wrap",
        }}
      >
        <label
          style={{
            display: "flex",
            alignItems: "center",
            gap: "0.5rem",
            margin: 0,
          }}
        >
          <input
            type="checkbox"
            checked={enabled}
            disabled={!config}
            onChange={(e) => setEnabled(e.target.checked)}
          />
          Auto-collect sources
        </label>
        <label
          style={{
            display: "flex",
            alignItems: "center",
            gap: "0.5rem",
            margin: 0,
          }}
        >
          Every
          <input
            className="form-input"
            type="number"
            style={{ width: "6rem" }}
            min={minMinutes}
            max={maxMinutes}
            value={minutes}
            disabled={!config}
            onChange={(e) =>
              setMinutes(parseInt(e.target.value, 10) || minMinutes)
            }
          />
          minutes
        </label>
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          disabled={!dirty || save.isPending}
          onClick={handleSave}
        >
          {save.isPending ? "Saving…" : "Save Schedule"}
        </button>
      </div>
      <div
        className="text-muted"
        style={{ fontSize: "0.85em", marginTop: "0.4rem" }}
      >
        Collects every Meraki, Cato, Cisco FMC, Palo Alto Panorama and Appgate
        SDP source that has an API key or password, one at a time, once its
        interval has passed since its last collection (Collect Now restarts the
        clock). {minMinutes} to {maxMinutes} minutes; a source can turn this off
        or set its own interval in its Edit form. AWS, Azure and GCP discovery
        is scheduled under Cloud Visibility.
      </div>
    </div>
  );
}
