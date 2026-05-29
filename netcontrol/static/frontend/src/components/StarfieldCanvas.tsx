import { useEffect, useRef } from 'react';

import { initStaticStarfield } from '@/lib/spaceStarfield';

interface Props {
  className: string;
  baseCount?: number;
}

export function StarfieldCanvas({ className, baseCount = 95 }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    if (!canvasRef.current) return;
    return initStaticStarfield({ canvas: canvasRef.current, baseCount });
  }, [baseCount]);

  return <canvas ref={canvasRef} className={className} aria-hidden="true" />;
}
