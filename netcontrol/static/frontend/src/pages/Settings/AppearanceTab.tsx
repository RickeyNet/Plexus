import { useState } from 'react';

import {
  applySpaceIntensity,
  applyTheme,
  readSavedSpaceIntensity,
  readSavedTheme,
  SPACE_INTENSITY_OPTIONS,
  SpaceIntensity,
  THEME_LABELS,
  ThemeName,
  VALID_THEMES,
} from '@/lib/appearance';

const INTENSITY_LABELS: Record<SpaceIntensity, string> = {
  off: 'Off',
  low: 'Low',
  medium: 'Medium',
  high: 'High',
};

export function AppearanceTab() {
  const [theme, setTheme] = useState<ThemeName>(readSavedTheme);
  const [intensity, setIntensity] = useState<SpaceIntensity>(readSavedSpaceIntensity);

  function onTheme(value: ThemeName) {
    setTheme(value);
    applyTheme(value);
  }

  function onIntensity(value: SpaceIntensity) {
    setIntensity(value);
    applySpaceIntensity(value);
  }

  return (
    <div className="card" style={{ padding: '1rem' }}>
      <h3 style={{ margin: '0 0 0.5rem 0' }}>Appearance</h3>
      <p className="card-description" style={{ marginBottom: '0.75rem' }}>
        Theme and background-depth preferences are saved to this browser.
      </p>

      <div style={{ display: 'grid', gap: '1rem', maxWidth: 320 }}>
        <div>
          <label className="form-label" htmlFor="appearance-theme">Theme</label>
          <select
            id="appearance-theme"
            className="form-select"
            value={theme}
            onChange={(e) => onTheme(e.target.value as ThemeName)}
          >
            {VALID_THEMES.map((t) => (
              <option key={t} value={t}>{THEME_LABELS[t]}</option>
            ))}
          </select>
        </div>

        <div>
          <label className="form-label" htmlFor="appearance-intensity">Space Depth Intensity</label>
          <select
            id="appearance-intensity"
            className="form-select"
            value={intensity}
            onChange={(e) => onIntensity(e.target.value as SpaceIntensity)}
          >
            {SPACE_INTENSITY_OPTIONS.map((i) => (
              <option key={i} value={i}>{INTENSITY_LABELS[i]}</option>
            ))}
          </select>
        </div>
      </div>
    </div>
  );
}
