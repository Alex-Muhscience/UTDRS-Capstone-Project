import { defineConfig, devices } from "@playwright/test"

/**
 * End-to-end tests against a real stack: the built dashboard (vite preview, which
 * proxies /api) in front of a running API gateway and core engine. Start those
 * with scripts/run-stack.sh, e.g. from the repository root:
 *
 *   scripts/run-stack.sh npm --prefix frontend run test:e2e
 *
 * E2E_BASE_URL runs them against an already running dashboard instead (the Docker
 * image, or a deployment). CHROMIUM_PATH points at an existing Chromium instead of
 * Playwright's own.
 */
const baseURL = process.env.E2E_BASE_URL ?? "http://localhost:4173"

export default defineConfig({
  testDir: "e2e",
  timeout: 60_000,
  expect: { timeout: 15_000 },
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL,
    trace: "retain-on-failure",
    launchOptions: process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {},
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: process.env.E2E_BASE_URL
    ? undefined
    : {
        command: "npm run build && npx vite preview --port 4173 --strictPort",
        url: baseURL,
        reuseExistingServer: !process.env.CI,
        timeout: 120_000,
      },
})
