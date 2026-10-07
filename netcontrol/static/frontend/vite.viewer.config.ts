import { defineConfig } from 'vite';
import { fileURLToPath, URL } from 'node:url';

// The tidy layout of the Topology page as one classic script for the
// standalone HTML export (see src/pages/Topology/viewerLayout.ts). Built
// after the app, into the same dist/ - which the app's build empties first.
export default defineConfig({
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: false,
    copyPublicDir: false,
    lib: {
      entry: fileURLToPath(new URL('./src/pages/Topology/viewerLayout.ts', import.meta.url)),
      name: 'PlexusLayout',
      formats: ['iife'],
      fileName: () => 'viewer-layout.js',
    },
  },
});
