import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// In dev the SPA runs on :5173 and the server on :8000; proxy /api so the browser's basic-auth credentials and
// the SSE live log work same-origin, exactly like production (where the server serves the SPA itself).
const SERVER = process.env.BOXCUTTER_SERVER || 'http://localhost:8000'

export default defineConfig({
  plugins: [vue()],
  server: {
    host: true,
    port: 5173,
    proxy: { '/api': SERVER },
  },
})
