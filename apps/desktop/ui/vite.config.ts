import { defineConfig } from 'vite'
import solid from 'vite-plugin-solid'

// The desktop app is served by Tauri from the built `dist/`. In dev / browser
// preview we run the Vite server; the model catalog is a fixed DeepSeek list and
// the agent run is mocked (see src/api.ts), so no proxy or backend is needed.
export default defineConfig({
  plugins: [solid()],
  clearScreen: false,
  server: {
    port: 5178,
    strictPort: false,
  },
  build: {
    target: 'esnext',
    outDir: 'dist',
  },
})
