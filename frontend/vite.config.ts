import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
export default defineConfig({
  plugins: [react()],
  server: { proxy: { '/health': 'http://localhost:8000', '/v1': 'http://localhost:8000', '/admin': 'http://localhost:8000' } }
});
