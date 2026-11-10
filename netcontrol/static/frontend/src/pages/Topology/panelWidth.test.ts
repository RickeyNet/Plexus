import { describe, expect, it } from 'vitest';

import { DETAILS_PANEL_MIN_WIDTH, MAP_MIN_HEIGHT, draggedPanelWidth, mapFillHeight, mapPanelsCollide } from './helpers';

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

describe('mapPanelsCollide', () => {
  it('is true when search and details do not fit side by side', () => {
    expect(mapPanelsCollide(740)).toBe(true);
    expect(mapPanelsCollide(1019)).toBe(true);
  });

  it('is false on a wide map and before the map is measured', () => {
    expect(mapPanelsCollide(1020)).toBe(false);
    expect(mapPanelsCollide(1600)).toBe(false);
    expect(mapPanelsCollide(0)).toBe(false);
  });
});

describe('mapFillHeight', () => {
  it('fills the window below the map top, less what stays under it', () => {
    expect(mapFillHeight(900, 300, 60)).toBe(540);
  });

  it('shrinks when the toolbar wraps or a card opens above the map', () => {
    expect(mapFillHeight(900, 380.5, 60)).toBe(459);
  });

  it('never goes under the minimum', () => {
    expect(mapFillHeight(600, 500, 60)).toBe(MAP_MIN_HEIGHT);
  });
});
