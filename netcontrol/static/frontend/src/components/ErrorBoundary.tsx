import { Component, type ErrorInfo, type ReactNode } from 'react';

interface Props {
  children: ReactNode;
  // Changing this value clears a caught error - pass the route path so
  // navigating away from a broken page recovers without a manual reload.
  resetKey?: string;
}

interface State {
  error: Error | null;
}

// A lazy route chunk import() that rejects (its hashed filename no longer
// exists after a deploy) surfaces as one of these. We show a "reload to get
// the new version" affordance rather than a generic crash for this case.
function isChunkLoadError(error: Error): boolean {
  const msg = error?.message || '';
  return (
    error?.name === 'ChunkLoadError' ||
    /Loading (CSS )?chunk \d+ failed/i.test(msg) ||
    /Failed to fetch dynamically imported module/i.test(msg) ||
    /error loading dynamically imported module/i.test(msg)
  );
}

// Route-level error boundary. Without one, any render throw or lazy-chunk
// load failure propagates to the root and React unmounts the whole tree to a
// blank screen. This contains the failure to the content area (the sidebar
// and nav chrome stay usable) and offers a recovery path.
export class ErrorBoundary extends Component<Props, State> {
  override state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  override componentDidUpdate(prevProps: Props) {
    if (this.state.error && prevProps.resetKey !== this.props.resetKey) {
      this.setState({ error: null });
    }
  }

  override componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('Unhandled UI error:', error, info.componentStack);
  }

  override render() {
    const { error } = this.state;
    if (!error) return this.props.children;

    const chunkError = isChunkLoadError(error);
    return (
      <div className="glass-card card" style={{ margin: '2rem', maxWidth: 640 }}>
        <div className="card-body" style={{ padding: '2rem' }}>
          <h2 className="gradient-text" style={{ marginTop: 0 }}>
            {chunkError ? 'A new version is available' : 'Something went wrong'}
          </h2>
          <p style={{ color: 'var(--text-secondary)' }}>
            {chunkError
              ? 'This page could not load because the app was updated since you opened it. Reload to get the latest version.'
              : 'An unexpected error occurred while rendering this page. Try reloading, or return to the dashboard.'}
          </p>
          {!chunkError && (
            <pre
              style={{
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                background: 'var(--bg-elevated, rgba(0,0,0,0.25))',
                padding: '0.75rem',
                borderRadius: 8,
                fontSize: '0.8rem',
                maxHeight: 160,
                overflow: 'auto',
              }}
            >
              {error.message}
            </pre>
          )}
          <div style={{ display: 'flex', gap: '0.75rem', marginTop: '1.25rem' }}>
            <button className="btn btn-primary" onClick={() => window.location.reload()}>
              Reload
            </button>
            {!chunkError && (
              <button
                className="btn"
                onClick={() => {
                  window.location.href = '/frontend/';
                }}
              >
                Go to dashboard
              </button>
            )}
          </div>
        </div>
      </div>
    );
  }
}
