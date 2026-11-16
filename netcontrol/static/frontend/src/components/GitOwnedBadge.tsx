import { type GitOwnership, isGitOwned } from '@/api/gitSources';

import { Badge } from './Badge';

/**
 * The "Git: <source> @ <commit>" pill on a template, playbook or config
 * context a Git source owns; nothing for a record written in Plexus.
 */
export function GitOwnedBadge({ record }: { record: GitOwnership }) {
  if (!isGitOwned(record)) return null;
  const source = record.git_source_name || `source #${record.git_source_id}`;
  const commit = (record.git_commit ?? '').slice(0, 10);
  const where = [record.git_path, commit && `at ${commit}`].filter(Boolean).join(' ');
  const title = `Managed by the Git source ${source}${where ? ` (${where})` : ''}. Change it in the repository and sync.`;
  return (
    <Badge tone="info" size="sm" title={title}>
      Git: {source}
      {commit ? ` @ ${commit}` : ''}
    </Badge>
  );
}
