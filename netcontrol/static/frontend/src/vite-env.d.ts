// Stylesheets are imported for their side effect only (main.tsx); Vite
// bundles them. Declared here rather than through `vite/client`, whose
// ImportMeta.glob would clash with the narrower one api/querySignal.test.ts
// declares for itself.
declare module '*.css';
