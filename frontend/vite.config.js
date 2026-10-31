import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    // The API's CORS only allows port 3000: fail loudly instead of silently moving to 3001.
    strictPort: true
  }
})

