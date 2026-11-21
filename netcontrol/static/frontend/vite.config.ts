import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath, URL } from 'node:url';

// The graph embed page (/api/graphs/{id}/embed, netcontrol/routes/graph_export.py)
// is server-rendered HTML outside the SPA and loads ECharts as one classic
// script. Copy the locked echarts package's prebuilt file to a fixed, unhashed
// path in dist/ so the app serves it itself: no CDN, and it works air-gapped.
// graph_export.ECHARTS_SCRIPT_SRC names the same path.
const ECHARTS_EMBED_FILE = 'vendor/echarts.min.js';

function echartsEmbedScript(): Plugin {
  return {
    name: 'plexus-echarts-embed-script',
    apply: 'build',
    generateBundle() {
      const source = createRequire(import.meta.url).resolve('echarts/dist/echarts.min.js');
      this.emitFile({ type: 'asset', fileName: ECHARTS_EMBED_FILE, source: readFileSync(source) });
    },
  };
}

// FastAPI serves the built bundle from the site root. The dev server runs on 5173
// and proxies /api, /static and /ws (WebSocket job/deploy/drift streams) →
// http://127.0.0.1:8080 so cookie auth works against the real backend without
// touching CORS.
const BACKEND_URL = process.env.PLEXUS_BACKEND_URL ?? 'http://127.0.0.1:8080';

export default defineConfig({
  base: '/',
  plugins: [react(), echartsEmbedScript()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // No production source maps: /assets is served without authentication
    // and nothing (no error reporter) consumes them. Use `vite build
    // --sourcemap` locally when a map is needed for debugging.
    sourcemap: false,
    rolldownOptions: {
      output: {
        // Pull the heavy viz libraries into their own vendor chunks. echarts is
        // imported by several lazy pages (Dashboard, DeviceDetail, Reports,
        // TrafficAnalysis); without this it gets duplicated into each page
        // chunk. A shared chunk is fetched once and cached across them. Each
        // chunk stays lazy - it's only requested when a page that uses it
        // loads - and splitting vendor from page code means editing a page no
        // longer busts the big library cache.
        //
        // Rolldown-native advancedChunks (the deprecated manualChunks compat
        // path silently kept React inside the codemirror group even when the
        // function returned 'react-vendor'). Groups match in order: React
        // must come first, or @uiw/react-codemirror drags it into the
        // codemirror chunk and the entry statically imports the ~488 KB
        // editor bundle on every page load.
        advancedChunks: {
          groups: [
            { name: 'react-vendor', test: /node_modules[\\/](react|react-dom|scheduler)[\\/]/ },
            { name: 'echarts', test: /node_modules[\\/](echarts|zrender)[\\/]/ },
            { name: 'vis-network', test: /node_modules[\\/](vis-network|vis-data|vis-util)[\\/]/ },
            { name: 'codemirror', test: /node_modules[\\/](@codemirror|@lezer|@uiw|codemirror)[\\/]/ },
          ],
        },
      },
    },
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': {
        target: BACKEND_URL,
        changeOrigin: false,
        secure: false,
      },
      '/static': {
        target: BACKEND_URL,
        changeOrigin: false,
        secure: false,
      },
      '/ws': {
        target: BACKEND_URL,
        ws: true,
        changeOrigin: false,
      },
    },
  },
});
