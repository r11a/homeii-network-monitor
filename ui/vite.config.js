import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  test: { environment: 'jsdom', setupFiles: ['./src/test-setup.js'], restoreMocks: true },
  base: './',
  plugins: [react()],
  server: {
    proxy: {
      '/api': process.env.HOMEII_API_TARGET || 'http://127.0.0.1:8383',
      '/logo': process.env.HOMEII_API_TARGET || 'http://127.0.0.1:8383',
    },
  },
})
