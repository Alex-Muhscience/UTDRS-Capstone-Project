/// <reference types="vitest/config" />
import { fileURLToPath, URL } from "node:url"

import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

// In development and preview, /api is proxied to the gateway so the browser sees one origin.
const gateway = process.env.UTDRS_GATEWAY_URL ?? "http://localhost:8000"
const proxy = { "/api": { target: gateway, changeOrigin: true } }

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  server: { port: 5173, proxy },
  preview: { port: 4173, proxy },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    css: false,
    // Node's fetch needs absolute URLs; tests stub fetch and match on paths.
    env: { VITE_API_URL: "http://gateway.test" },
  },
})
