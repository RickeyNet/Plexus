import { useEffect, useRef } from 'react';

import { initStarfield } from '@/lib/spaceStarfield';

// Mirrors the legacy SPA's `.animated-bg` + `#app-particles` block. All the CSS
// (.space-depth, .space-nebula, .gradient-orb, .app-particles) lives in the
// shared stylesheet, so we just need the DOM structure and a starfield init.
export function AnimatedBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const hostRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!canvasRef.current || !hostRef.current) return;
    return initStarfield({
      canvas: canvasRef.current,
      host: hostRef.current,
      baseCount: 95,
      linkDistance: 0,
    });
  }, []);

  return (
    <>
      <div className="animated-bg" ref={hostRef}>
        <div className="space-depth space-depth-app" aria-hidden="true">
          <div className="space-nebula nebula-a" />
          <div className="space-nebula nebula-b" />
          <div className="space-nebula nebula-c" />
          <div className="space-vignette" />
        </div>
        <div className="gradient-orb orb-1" />
        <div className="gradient-orb orb-2" />
        <div className="gradient-orb orb-3" />
      </div>
      <canvas ref={canvasRef} className="app-particles" />
    </>
  );
}
