/**
 * The Topology page's tidy layout for the standalone HTML export.
 *
 * `npm run build` also bundles this file on its own (vite.viewer.config.ts)
 * as `dist/viewer-layout.js`, a script that defines the global
 * `PlexusLayout`. The export inlines it, so the exported map is laid out by
 * the same code as the page: a region per source, each network a tree (a
 * hub's links to its spokes drawn as a comb), and the links between sources
 * routed over the regions.
 */

export { crowdedGroups, fitTitles, labelWidth, tidyTree } from './layout';
export { nodeProvider } from './helpers';
export { distanceToRoute, routeSourceLinks, traceRoute } from './routes';
