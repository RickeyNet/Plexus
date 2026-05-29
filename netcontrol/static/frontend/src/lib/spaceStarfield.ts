// Static starfield: draws fixed stars once and only redraws on resize or theme
// change. No animation loop, so it stays cheap even with performance mode on.

export interface StarfieldOptions {
  canvas: HTMLCanvasElement;
  baseCount?: number;
}

interface Star {
  near: boolean;
  x: number;
  y: number;
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

function getIntensity(): number {
  const raw = getComputedStyle(document.documentElement).getPropertyValue('--space-intensity-base').trim();
  const n = parseFloat(raw);
  return Number.isFinite(n) ? n : 1;
}

function readPalette(): { farRGB: [number, number, number]; nearRGB: [number, number, number] } {
  const style = getComputedStyle(document.documentElement);
  return {
    farRGB: parseRgbVar(style.getPropertyValue('--space-star-far-rgb'), [150, 190, 255]),
    nearRGB: parseRgbVar(style.getPropertyValue('--space-star-near-rgb'), [225, 240, 255]),
  };
}

function createStars(count: number, width: number, height: number): Star[] {
  return Array.from({ length: count }, (_, i) => {
    const near = i < Math.floor(count * 0.35);
    return {
      near,
      x: Math.random() * width,
      y: Math.random() * height,
      size: near ? 0.7 + Math.random() * 1.8 : 0.4 + Math.random() * 1.0,
      alpha: near ? 0.3 + Math.random() * 0.55 : 0.15 + Math.random() * 0.35,
      twinkle: Math.random() * Math.PI * 2,
    };
  });
}

function drawStars(
  ctx: CanvasRenderingContext2D,
  stars: Star[],
  farRGB: [number, number, number],
  nearRGB: [number, number, number],
): void {
  const intensity = getIntensity();
  ctx.clearRect(0, 0, ctx.canvas.width, ctx.canvas.height);
  if (intensity <= 0) return;

  const maxStars = Math.max(4, Math.floor(stars.length * intensity));
  for (let i = 0; i < maxStars; i++) {
    const s = stars[i];
    const twinkleAlpha = 0.75 + Math.sin(s.twinkle) * 0.25;
    const rgb = s.near ? nearRGB : farRGB;

    ctx.beginPath();
    ctx.arc(s.x, s.y, s.size * (s.near ? 1 : 0.85), 0, Math.PI * 2);
    ctx.fillStyle = `rgba(${rgb[0]}, ${rgb[1]}, ${rgb[2]}, ${Math.max(0.02, s.alpha * twinkleAlpha * intensity)})`;
    ctx.fill();
  }
}

export function initStaticStarfield(opts: StarfieldOptions): () => void {
  const { canvas, baseCount = 90 } = opts;
  const ctx = canvas.getContext('2d');
  if (!ctx) return () => {};

  let stars: Star[] = [];
  let palette = readPalette();

  const redraw = () => {
    canvas.width = canvas.offsetWidth || window.innerWidth;
    canvas.height = canvas.offsetHeight || window.innerHeight;
    stars = createStars(baseCount, canvas.width, canvas.height);
    palette = readPalette();
    drawStars(ctx, stars, palette.farRGB, palette.nearRGB);
  };

  const onThemeChange = () => {
    palette = readPalette();
    drawStars(ctx, stars, palette.farRGB, palette.nearRGB);
  };

  redraw();
  window.addEventListener('resize', redraw);

  const themeObs = new MutationObserver(onThemeChange);
  themeObs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

  return () => {
    themeObs.disconnect();
    window.removeEventListener('resize', redraw);
  };
}
