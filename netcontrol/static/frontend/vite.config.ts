import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath, URL } from 'node:url';

// FastAPI serves the built bundle at /frontend/. The dev server runs on 5173
// and proxies /api → http://127.0.0.1:8080 so cookie auth works against the
// real backend without touching CORS.
const BACKEND_URL = process.env.PLEXUS_BACKEND_URL ?? 'http://127.0.0.1:8080';

export default defineConfig({
  base: '/frontend/',
  plugins: [react()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: true,
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
    },
  },
});
