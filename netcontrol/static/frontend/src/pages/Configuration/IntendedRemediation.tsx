import { useId, useState } from 'react';
import { Link } from 'react-router';

import { useAuthStatus } from '@/api/auth';
import { useCredentials } from '@/api/compliance';
import {
  type RemediationDeploymentResult,
  useCreateRemediationDeployments,
  useHostRemediation,
} from '@/api/intendedRemediation';
import { BusyButton } from '@/components/BusyButton';
import { Callout } from '@/components/Callout';
import { CopyButton } from '@/components/CopyButton';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { useCanWriteGroup } from '@/lib/objectScope';
import { canUseFeature } from '@/lib/tabGating';

import { commandsText, deploymentHref, remediationSummary } from './intendedHelpers';
import { writeControl } from './scopeGating';

/** What the create call did, with a link to each deployment. */
export function DeploymentResult({ result }: { result: RemediationDeploymentResult }) {
  const [first] = result.deployments;
  return (
    <Callout tone={first ? 'success' : 'warning'} role="status">
      {first ? (
        <>
          Deployment <Link to={deploymentHref(first.id)}>#{first.id}</Link> planned
          {first.requires_approval ? '; it needs approval before it runs.' : '. Review and execute it under Deployments.'}
        </>
      ) : (
        <>No deployment was created: {result.skipped[0]?.reason ?? 'nothing to push.'}</>
      )}
    </Callout>
  );
}

/**
 * A host's remediation next to its diff: the commands that make the device
 * match (removals before additions, parents first), Copy, and Create
 * deployment, which plans a deployment with a chosen credential (Deployments
 * feature and write on the host's group).
 */
export function RemediationSection({ hostId, groupId }: { hostId: number; groupId: number | null }) {
  const q = useHostRemediation(hostId);
  const auth = useAuthStatus().data;
  const canDeploy = canUseFeature('deployments', auth);
  const canWrite = useCanWriteGroup(groupId);
  const fid = useId();
  const creds = useCredentials();
  const create = useCreateRemediationDeployments();
  const [credentialId, setCredentialId] = useState<number | null>(null);
  const [result, setResult] = useState<RemediationDeploymentResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const r = q.data;

  const submit = async () => {
    if (credentialId == null) return;
    setError(null);
    setResult(null);
    try {
      setResult(await create.mutateAsync({ host_ids: [hostId], credential_id: credentialId }));
    } catch (err) {
      setError(`The deployment was not created: ${(err as Error).message}`);
    }
  };

  let body;
  if (q.isError && !r) body = <QueryError what="the remediation" query={q} />;
  else if (!r) body = <LoadingState text="Working out the remediation…" />;
  else if (r.state !== 'ok')
    body = (
      <Callout tone={r.state === 'unsupported' ? 'warning' : 'info'} title={r.state === 'unsupported' ? 'Not supported' : 'No remediation'}>
        {r.reason}
      </Callout>
    );
  else if (r.commands.length === 0)
    body = <EmptyState compact message="Nothing to push: the device matches its intended configuration." />;
  else
    body = (
      <div className="stack stack-sm">
        <div className="form-help">
          {remediationSummary(r)}. {r.platform} syntax; removals come first in each block.
        </div>
        <pre className="drift-diff-viewer" aria-label="Remediation commands">
          {commandsText(r.commands)}
        </pre>
        {canDeploy && (
          <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap', alignItems: 'flex-end' }}>
            <div className="form-group" style={{ margin: 0, minWidth: 220 }}>
              <label className="form-label" htmlFor={`${fid}-credential`}>
                SSH credential
              </label>
              <select
                id={`${fid}-credential`}
                className="form-select"
                value={credentialId ?? ''}
                onChange={(e) => setCredentialId(e.target.value ? Number(e.target.value) : null)}
              >
                <option value="">Select…</option>
                {(creds.data ?? []).map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                  </option>
                ))}
              </select>
            </div>
            <BusyButton
              className="btn btn-primary"
              busy={create.isPending}
              busyLabel="Creating…"
              {...writeControl(canWrite, credentialId == null)}
              onClick={() => void submit()}
            >
              Create deployment
            </BusyButton>
          </div>
        )}
      </div>
    );

  return (
    <section aria-label="Remediation">
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-1)' }}>
        <span style={{ fontWeight: 600 }}>Remediation</span>
        <span className="toolbar-spacer" />
        <CopyButton text={commandsText(r?.commands ?? [])} label="Copy commands" disabled={!r?.commands.length} />
      </div>
      {r?.notes.map((note) => (
        <Callout key={note} tone="warning">
          {note}
        </Callout>
      ))}
      {error && <Callout tone="danger">{error}</Callout>}
      {result && <DeploymentResult result={result} />}
      {body}
    </section>
  );
}
