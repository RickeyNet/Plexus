// Theme + space-depth-intensity controls. Mirrors the legacy app.js
// applyTheme/applySpaceSettings flow so existing CSS (data-theme + the
// --space-intensity-user variable) keeps working.

export const THEME_KEY = 'plexus-theme';
export const SPACE_INTENSITY_KEY = 'plexus_space_intensity';

export const VALID_THEMES = [
  'forest',
  'dark-modern',
  'astral',
  'light',
  'void',
  'coral',
  'sandstone',
  'voyager',
] as const;
export type ThemeName = (typeof VALID_THEMES)[number];

export const THEME_LABELS: Record<ThemeName, string> = {
  forest: 'Forest',
  'dark-modern': 'Dark',
  astral: 'Astral',
  light: 'Light',
  void: 'Void',
  coral: 'Coral',
  sandstone: 'Sandstone',
  voyager: 'Voyager',
};

export const DEFAULT_THEME: ThemeName = 'sandstone';

export const SPACE_INTENSITY_MAP = {
  off: 0,
  low: 0.45,
  medium: 0.8,
  high: 1.0,
} as const;
export type SpaceIntensity = keyof typeof SPACE_INTENSITY_MAP;
export const SPACE_INTENSITY_OPTIONS: SpaceIntensity[] = ['off', 'low', 'medium', 'high'];
export const DEFAULT_SPACE_INTENSITY: SpaceIntensity = 'medium';

function isTheme(value: string | null): value is ThemeName {
  return !!value && (VALID_THEMES as readonly string[]).includes(value);
}

function isIntensity(value: string | null): value is SpaceIntensity {
  return !!value && Object.prototype.hasOwnProperty.call(SPACE_INTENSITY_MAP, value);
}

export function readSavedTheme(): ThemeName {
  const v = localStorage.getItem(THEME_KEY);
  return isTheme(v) ? v : DEFAULT_THEME;
}

export function readSavedSpaceIntensity(): SpaceIntensity {
  const v = localStorage.getItem(SPACE_INTENSITY_KEY);
  return isIntensity(v) ? v : DEFAULT_SPACE_INTENSITY;
}

export function applyTheme(theme: ThemeName): void {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem(THEME_KEY, theme);
}

export function applySpaceIntensity(intensity: SpaceIntensity): void {
  const scalar = SPACE_INTENSITY_MAP[intensity];
  document.documentElement.style.setProperty('--space-intensity-user', String(scalar));
  localStorage.setItem(SPACE_INTENSITY_KEY, intensity);
}

export function initAppearance(): void {
  applyTheme(readSavedTheme());
  applySpaceIntensity(readSavedSpaceIntensity());
}
