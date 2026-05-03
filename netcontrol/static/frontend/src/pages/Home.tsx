import { useAuthStatus } from '@/api/auth';

export function Home() {
  const { data, isPending, error } = useAuthStatus();

  return (
    <>
      <div className="page-header">
        <h2>Plexus — React Frontend</h2>
      </div>

      <div className="glass-card card">
        <p style={{ marginBottom: '1rem' }}>
          Phase 1.1 skeleton. Vite + React 18 + TypeScript, served by FastAPI
          at <code>/frontend/</code>. Visual styling reuses the legacy
          stylesheet at <code>/static/css/style.css</code>.
        </p>

        <h3 style={{ marginBottom: '0.5rem' }}>Backend connectivity</h3>

        {isPending && <div className="skeleton-loader" style={{ height: '60px' }} />}

        {error && (
          <div className="glass-card card" style={{ borderColor: 'var(--danger)' }}>
            <strong>Auth status request failed:</strong> {error.message}
          </div>
        )}

        {data && (
          <>
            <p style={{ marginBottom: '0.5rem' }}>
              <span className={`badge ${data.authenticated ? 'badge-success' : 'badge-warning'}`}>
                {data.authenticated
                  ? `Authenticated as ${data.username ?? 'unknown user'}`
                  : 'Not authenticated'}
              </span>
            </p>
            <pre style={{ margin: 0, fontSize: '0.85em', opacity: 0.85 }}>
              {JSON.stringify(data, null, 2)}
            </pre>
          </>
        )}
      </div>
    </>
  );
}
