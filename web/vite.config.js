import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// In dev the SPA runs on :5173 and the API on :8000. Proxy the API's docs (and openapi schema) so they are
// reachable on the SAME port as the app — http://localhost:5173/docs. In production the API serves the SPA
// and /docs on one origin already, so the relative link "just works" there too.
const API = process.env.VITE_API_BASE || 'http://localhost:8000'

export default defineConfig({
  plugins: [vue()],
  server: {
    host: true,
    port: 5173,
    proxy: {
      '/docs': API,
      '/redoc': API,
      '/openapi.json': API,
    },
  },
})
