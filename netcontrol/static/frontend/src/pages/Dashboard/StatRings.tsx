import { useEffect, useRef } from 'react';

const RADIUS = 34;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

function isReducedMotion() {
  return document.body.classList.contains('reduced-motion');
}

interface RingProps {
  label: string;
  value: number;
  max: number;
}

function Ring({ label, value, max }: RingProps) {
  const valueRef = useRef<HTMLDivElement>(null);
  const ringRef = useRef<SVGCircleElement>(null);

  useEffect(() => {
    const valueEl = valueRef.current;
    const ringEl = ringRef.current;
    if (!valueEl || !ringEl) return;

    const clamped = Math.min(value, max);
    const ratio = max > 0 ? clamped / max : 0;
    const offset = CIRCUMFERENCE * (1 - ratio);

    ringEl.style.strokeDasharray = String(CIRCUMFERENCE);
    ringEl.style.strokeDashoffset = String(CIRCUMFERENCE);
    const ringRaf = requestAnimationFrame(() => {
      ringEl.style.strokeDashoffset = String(offset);
    });

    if (value === 0) {
      valueEl.textContent = '0';
      return () => cancelAnimationFrame(ringRaf);
    }
    if (isReducedMotion()) {
      valueEl.textContent = String(value);
      return () => cancelAnimationFrame(ringRaf);
    }

    const duration = 600;
    const start = performance.now();
    let counterRaf = 0;
    const step = (now: number) => {
      const progress = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      valueEl.textContent = String(Math.round(eased * value));
      if (progress < 1) counterRaf = requestAnimationFrame(step);
    };
    counterRaf = requestAnimationFrame(step);

    return () => {
      cancelAnimationFrame(ringRaf);
      cancelAnimationFrame(counterRaf);
    };
  }, [value, max]);

  return (
    <div className="stat-card stat-card-ring">
      <div className="stat-ring-wrap">
        <svg className="stat-ring" viewBox="0 0 80 80">
          <circle className="stat-ring-bg" cx="40" cy="40" r={RADIUS} />
          <circle ref={ringRef} className="stat-ring-fill" cx="40" cy="40" r={RADIUS} />
        </svg>
        <div ref={valueRef} className="stat-ring-value">
          -
        </div>
      </div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

interface StatRingsProps {
  hosts: number;
  playbooks: number;
  jobs: number;
}

export function StatRings({ hosts, playbooks, jobs }: StatRingsProps) {
  const max = Math.max(hosts, playbooks, jobs, 1);
  return (
    <div className="stats-grid">
      <Ring label="Total Hosts" value={hosts} max={max} />
      <Ring label="Playbooks" value={playbooks} max={max} />
      <Ring label="Total Jobs" value={jobs} max={max} />
    </div>
  );
}
