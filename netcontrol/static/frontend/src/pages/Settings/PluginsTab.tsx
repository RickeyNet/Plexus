import { usePluginManifest, type PluginStatus } from '@/api/plugins';
import { Badge } from '@/components/Badge';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import type { Tone } from '@/lib/severity';

const STATUS_TONE: Record<PluginStatus, Tone> = {
  active: 'success',
  loaded: 'info',
  disabled: 'neutral',
  failed: 'danger',
};

function versionRange(min?: string | null, max?: string | null): string {
  if (min && max) return `${min} to ${max}`;
  if (min) return `${min} or later`;
  if (max) return `up to ${max}`;
  return 'any';
}

/** Installed plugins, read-only: which load is set by PLEXUS_PLUGINS on the server. */
export function PluginsTab() {
  const manifest = usePluginManifest();
  if (manifest.isError && !manifest.data) return <QueryError what="plugins" query={manifest} />;
  if (!manifest.data) return <LoadingState />;

  const plugins = manifest.data.plugins;
  if (plugins.length === 0) {
    return (
      <EmptyState
        compact
        message="No plugins are installed."
        description="Install a plugin package on the server and list its name in PLEXUS_PLUGINS, then restart Plexus."
      />
    );
  }
  return (
    <DataTable compact aria-label="Installed plugins">
      <thead>
        <tr>
          <th>Plugin</th>
          <th>Version</th>
          <th>Status</th>
          <th>Feature key</th>
          <th>Plexus versions</th>
          <th>Details</th>
        </tr>
      </thead>
      <tbody>
        {plugins.map((p) => (
          <tr key={p.name}>
            <td>
              <div>{p.label || p.name}</div>
              <div className="text-muted" style={{ fontSize: '0.85em' }}>
                {p.name}
                {p.description ? ` · ${p.description}` : ''}
              </div>
            </td>
            <td>{p.version || '—'}</td>
            <td>
              <Badge size="sm" tone={STATUS_TONE[p.status] ?? 'neutral'}>{p.status}</Badge>
            </td>
            <td><code>{p.feature}</code></td>
            <td>{versionRange(p.min_plexus_version, p.max_plexus_version)}</td>
            <td>
              {p.errors && p.errors.length > 0 ? (
                <ul className="error" style={{ margin: 0, paddingLeft: '1rem' }}>
                  {p.errors.map((e) => (
                    <li key={e}>{e}</li>
                  ))}
                </ul>
              ) : (
                <span className="text-muted">
                  {p.source ? `From ${p.source}` : ''}
                  {p.migrations_applied ? ` · ${p.migrations_applied} migration(s) applied this start` : ''}
                </span>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </DataTable>
  );
}
