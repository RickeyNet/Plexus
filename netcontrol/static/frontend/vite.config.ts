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
