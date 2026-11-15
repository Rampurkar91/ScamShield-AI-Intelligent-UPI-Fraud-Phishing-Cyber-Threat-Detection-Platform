import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The proxy is server-side only; browsers use same-origin /api requests.
const backend = process.env.BACKEND_PROXY_TARGET || 'http://127.0.0.1:8000';
export default defineConfig({
  plugins: [react()],
  server: { allowedHosts: true, proxy: { '/api': backend, '/health': backend } },
});
