/// <reference types="vitest/config" />
import { fileURLToPath, URL } from "node:url"

import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig, loadEnv } from "vite"

// In development and preview, /api is proxied to the gateway so the browser sees one origin.
const gateway = process.env.UTDRS_GATEWAY_URL ?? "http://localhost:8000"
const proxy = { "/api": { target: gateway, changeOrigin: true } }

// On Vercel (which sets VERCEL during its builds), the dashboard calls the API gateway on
// Render. The address is in .env.vercel, under a name nothing else sets: the Vercel
// project's own settings cannot override it (an empty VITE_API_URL there would).
const deployed = process.env.VERCEL ? loadEnv("vercel", process.cwd(), "UTDRS_DEPLOY_") : {}

export default defineConfig({
  plugins: [react(), tailwindcss()],
  define: { __DEPLOYED_API_URL__: JSON.stringify(deployed.UTDRS_DEPLOY_API_URL ?? "") },
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
