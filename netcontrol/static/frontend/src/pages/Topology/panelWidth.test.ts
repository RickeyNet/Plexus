import { describe, expect, it } from 'vitest';

import { DETAILS_PANEL_MIN_WIDTH, draggedPanelWidth } from './helpers';

describe('draggedPanelWidth', () => {
  it('widens when the left edge is dragged left', () => {
    expect(draggedPanelWidth(460, 1000, 800, 1600)).toBe(660);
  });

  it('narrows when the left edge is dragged right', () => {
    expect(draggedPanelWidth(660, 800, 900, 1600)).toBe(560);
  });

  it('never goes narrower than the minimum', () => {
    expect(draggedPanelWidth(460, 800, 1200, 1600)).toBe(DETAILS_PANEL_MIN_WIDTH);
  });

  it('never goes wider than the map minus its margins', () => {
    expect(draggedPanelWidth(460, 1500, 0, 1600)).toBe(1576);
  });

  it('keeps the minimum even when the map is narrower than it', () => {
    expect(draggedPanelWidth(380, 300, 0, 300)).toBe(DETAILS_PANEL_MIN_WIDTH);
    expect(draggedPanelWidth(380, 300, 400, 300)).toBe(DETAILS_PANEL_MIN_WIDTH);
  });

  it('rounds to a whole pixel', () => {
    expect(draggedPanelWidth(460, 800.4, 700, 1600)).toBe(560);
  });
});
