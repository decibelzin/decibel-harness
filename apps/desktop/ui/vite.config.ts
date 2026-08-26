import { defineConfig } from 'vite'
import solid from 'vite-plugin-solid'

// The desktop app is served by Tauri from the built `dist/`. In dev / browser
// preview we run the Vite server and proxy the public OpenRouter catalog through
// it, so the model selector shows live data without a CORS problem and without
// the Rust backend running. In the real Tauri build the Rust side fetches
// instead (see src/api.ts).
export default defineConfig({
  plugins: [solid()],
  clearScreen: false,
  server: {
    port: 5178,
    strictPort: false,
    proxy: {
      '/or': {
        target: 'https://openrouter.ai',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/or/, ''),
      },
    },
  },
  build: {
    target: 'esnext',
    outDir: 'dist',
  },
})
