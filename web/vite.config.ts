import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// O build vai direto para dentro do pacote Go que embute o painel.
// Em desenvolvimento, /api é encaminhado para um heimdalldns rodando local.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    outDir: '../internal/webui/dist',
    emptyOutDir: true,
    chunkSizeWarningLimit: 900,
  },
  server: {
    proxy: {
      '/api': { target: process.env.HEIMDALL_API ?? 'http://127.0.0.1:8053', changeOrigin: false },
    },
  },
})
