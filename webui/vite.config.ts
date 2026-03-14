import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyDirBeforeWrite: true,
  },
  // Base path for assets when served under /ui/
  base: '/ui/',
})
