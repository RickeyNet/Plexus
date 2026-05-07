// Port of the legacy starfield (netcontrol/static/js/app.js initSpaceStarfield).
// The legacy version supports user-configurable intensity + parallax via
// settings; here we hold those at sensible defaults and let `body.reduced-motion`
// (set by the performance toggle) gate animation, which is enough for parity.

export interface StarfieldOptions {
  canvas: HTMLCanvasElement;
  host: HTMLElement;
  baseCount?: number;
  linkDistance?: number;
  baseSpeed?: number;
}

interface Star {
  near: boolean;
  x: number;
  y: number;
  dx: number;
  dy: number;
  size: number;
  alpha: number;
  twinkle: number;
}

function parseRgbVar(rawValue: string, fallback: [number, number, number]): [number, number, number] {
  const m = (rawValue || '').trim().match(/^(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})$/);
  if (!m) return fallback;
  return [
    Math.min(255, parseInt(m[1], 10)),
    Math.min(255, parseInt(m[2], 10)),
    Math.min(255, parseInt(m[3], 10)),
  ];
}

function isReducedMotion(): boolean {
  return document.body.classList.contains('reduced-motion');
}

function getIntensity(): number {
  // Read --space-intensity-base from :root so themes that dim space FX still
  // apply. Default to 1.0 if unset or invalid.
  const raw = getComputedStyle(document.documentElement).getPropertyValue('--space-intensity-base').trim();
  const n = parseFloat(raw);
  return Number.isFinite(n) ? n : 1;
}

export function initStarfield(opts: StarfieldOptions): () => void {
  const { canvas, host, baseCount = 90, linkDistance = 0, baseSpeed = 0.06 } = opts;
  const ctx = canvas.getContext('2d');
  if (!ctx) return () => {};

  let animId: number | null = null;
  let slowTimer: number | null = null;
  let running = false;
  let stars: Star[] = [];
  let farRGB: [number, number, number] = [150, 190, 255];
  let nearRGB: [number, number, number] = [225, 240, 255];

  const updatePalette = () => {
    const style = getComputedStyle(document.documentElement);
    farRGB = parseRgbVar(style.getPropertyValue('--space-star-far-rgb'), [150, 190, 255]);
    nearRGB = parseRgbVar(style.getPropertyValue('--space-star-near-rgb'), [225, 240, 255]);
  };

  const createStars = () => {
    const w = canvas.width || 1;
    const h = canvas.height || 1;
    stars = Array.from({ length: baseCount }, (_, i) => {
      const near = i < Math.floor(baseCount * 0.35);
      const speed = near ? baseSpeed * (0.9 + Math.random() * 0.8) : baseSpeed * (0.2 + Math.random() * 0.35);
      return {
        near,
        x: Math.random() * w,
        y: Math.random() * h,
        dx: (Math.random() - 0.5) * speed,
        dy: (Math.random() - 0.5) * speed,
        size: near ? 0.7 + Math.random() * 1.8 : 0.4 + Math.random() * 1.0,
        alpha: near ? 0.3 + Math.random() * 0.55 : 0.15 + Math.random() * 0.35,
        twinkle: Math.random() * Math.PI * 2,
      };
    });
  };

  const resize = () => {
    canvas.width = canvas.offsetWidth || window.innerWidth;
    canvas.height = canvas.offsetHeight || window.innerHeight;
    updatePalette();
    createStars();
  };

  const wrapStar = (s: Star) => {
    if (s.x < -4) s.x = canvas.width + 4;
    else if (s.x > canvas.width + 4) s.x = -4;
    if (s.y < -4) s.y = canvas.height + 4;
    else if (s.y > canvas.height + 4) s.y = -4;
  };

  const draw = () => {
    if (!running) return;
    const intensity = getIntensity();
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    if (intensity <= 0) {
      if (slowTimer) clearTimeout(slowTimer);
      slowTimer = window.setTimeout(() => {
        animId = requestAnimationFrame(draw);
      }, 320);
      return;
    }

    const moving = !isReducedMotion();
    const maxStars = Math.max(4, Math.floor(stars.length * intensity));

    for (let i = 0; i < maxStars; i++) {
      const s = stars[i];
      s.twinkle += moving ? 0.02 : 0;
      const twinkleAlpha = 0.75 + Math.sin(s.twinkle) * 0.25;
      const rgb = s.near ? nearRGB : farRGB;

      ctx.beginPath();
      ctx.arc(s.x, s.y, s.size * (s.near ? 1 : 0.85), 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${rgb[0]}, ${rgb[1]}, ${rgb[2]}, ${Math.max(0.02, s.alpha * twinkleAlpha * intensity)})`;
      ctx.fill();

      if (moving) {
        s.x += s.dx;
        s.y += s.dy;
        wrapStar(s);
      }
    }

    if (linkDistance > 0) {
      for (let i = 0; i < maxStars; i++) {
        const a = stars[i];
        if (!a.near) continue;
        for (let j = i + 1; j < maxStars; j++) {
          const b = stars[j];
          if (!b.near) continue;
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist > linkDistance) continue;
          const alpha = (1 - dist / linkDistance) * 0.08 * intensity;
          if (alpha <= 0.002) continue;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.strokeStyle = `rgba(${nearRGB[0]}, ${nearRGB[1]}, ${nearRGB[2]}, ${alpha})`;
          ctx.lineWidth = 0.55;
          ctx.stroke();
        }
      }
    }

    if (!isReducedMotion() && Math.random() < 0.0035 * intensity) {
      const streakY = Math.random() * canvas.height;
      const streakX = Math.random() * canvas.width;
      const len = 45 + Math.random() * 130;
      const grad = ctx.createLinearGradient(streakX, streakY, streakX + len, streakY - len * 0.22);
      grad.addColorStop(0, `rgba(${nearRGB[0]}, ${nearRGB[1]}, ${nearRGB[2]}, 0)`);
      grad.addColorStop(0.45, `rgba(${nearRGB[0]}, ${nearRGB[1]}, ${nearRGB[2]}, ${0.14 * intensity})`);
      grad.addColorStop(1, `rgba(${nearRGB[0]}, ${nearRGB[1]}, ${nearRGB[2]}, 0)`);
      ctx.beginPath();
      ctx.strokeStyle = grad;
      ctx.lineWidth = 1.1;
      ctx.moveTo(streakX, streakY);
      ctx.lineTo(streakX + len, streakY - len * 0.22);
      ctx.stroke();
    }

    if (moving) {
      animId = requestAnimationFrame(draw);
    } else {
      if (slowTimer) clearTimeout(slowTimer);
      slowTimer = window.setTimeout(() => {
        animId = requestAnimationFrame(draw);
      }, 220);
    }
  };

  const syncRunning = () => {
    const visible = getComputedStyle(host).display !== 'none';
    if (visible && !running) {
      running = true;
      resize();
      animId = requestAnimationFrame(draw);
    } else if (!visible && running) {
      running = false;
      if (animId) cancelAnimationFrame(animId);
      if (slowTimer) clearTimeout(slowTimer);
      animId = null;
      slowTimer = null;
    }
  };

  resize();
  updatePalette();
  window.addEventListener('resize', resize);

  const themeObs = new MutationObserver(() => {
    updatePalette();
    syncRunning();
  });
  themeObs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

  const visObs = new MutationObserver(syncRunning);
  visObs.observe(host, { attributes: true, attributeFilter: ['style'] });
  syncRunning();

  return () => {
    themeObs.disconnect();
    visObs.disconnect();
    window.removeEventListener('resize', resize);
    if (animId) cancelAnimationFrame(animId);
    if (slowTimer) clearTimeout(slowTimer);
    running = false;
    animId = null;
    slowTimer = null;
  };
}
