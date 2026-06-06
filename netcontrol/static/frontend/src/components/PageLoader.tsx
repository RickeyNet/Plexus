import { useEffect, useState } from 'react';

// Suspense fallback shown while a lazy route chunk downloads. The spinner is
// delayed so prefetched or already-cached chunks (which resolve in well under
// delayMs) never flash it - only a genuinely slow first load shows feedback,
// which avoids the jarring blank-then-flash on fast navigations.
export function PageLoader({ delayMs = 150 }: { delayMs?: number }) {
  const [show, setShow] = useState(false);

  useEffect(() => {
    const id = window.setTimeout(() => setShow(true), delayMs);
    return () => window.clearTimeout(id);
  }, [delayMs]);

  if (!show) return null;

  return (
    <div className="loading" role="status" aria-live="polite" aria-busy="true">
      <span
        className="backup-spinner"
        style={{ width: 20, height: 20, borderWidth: 3 }}
        aria-hidden="true"
      />
    </div>
  );
}
