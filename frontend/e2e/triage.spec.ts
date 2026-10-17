import { randomBytes } from "node:crypto"

import { expect, test } from "@playwright/test"

/**
 * The golden path through the real system: an analyst registers, sends an event,
 * the core engine flags it, and the analyst triages the alert it raised.
 */
test("an event becomes an alert that an analyst can triage", async ({ page }) => {
  const username = `e2e_${randomBytes(4).toString("hex")}`
  const password = randomBytes(12).toString("base64url")

  await page.goto("/register")
  await page.getByLabel("First name").fill("Edith")
  await page.getByLabel("Username").fill(username)
  await page.getByLabel("Email").fill(`${username}@example.com`)
  await page.getByLabel("Password").fill(password)
  await page.getByRole("button", { name: "Create account" }).click()

  await expect(page.getByRole("heading", { name: "Welcome back, Edith" })).toBeVisible()
  await expect(page.getByText("Detection online")).toBeVisible()

  await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Events" }).click()
  await page.getByRole("button", { name: "Send test event" }).click()
  await page.getByRole("dialog").getByText("Shadow copies deleted").click()
  await page.getByRole("button", { name: "Send event" }).click()

  await expect(page.getByRole("heading", { name: "Shadow copies deleted" })).toBeVisible()
  await expect(page.getByText("Threat detected")).toBeVisible()
  await page.getByRole("link", { name: "Open the alert" }).click()

  // The ML detector names it, unless the demo data's "shadow-copy-deletion" rule is loaded:
  // signature rules from the catalogue take priority.
  await expect(
    page.getByRole("heading", { name: /^(Potential Ransomware Activity: Recovery Inhibited|shadow-copy-deletion)$/ }),
  ).toBeVisible()
  await expect(page.getByRole("link", { name: /T1490/ })).toBeVisible()

  await page.getByLabel("Note").fill("Isolated the laptop from the network.")
  await page.getByRole("button", { name: "Start investigating" }).click()
  await expect(page.getByRole("button", { name: "Resolve" })).toBeVisible()
  await page.getByRole("button", { name: "Assign to me" }).click()
  await expect(page.getByText("Assigned to you", { exact: true })).toBeVisible()
  await page.getByRole("button", { name: "Resolve" }).click()
  await expect(page.getByRole("button", { name: "Close" })).toBeVisible()
  await expect(page.getByText("Isolated the laptop from the network.")).toBeVisible()

  await page.getByRole("button", { name: "Sign out" }).click()
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible()
})

test("a routine event is analysed and found clean", async ({ page, request }) => {
  const username = `e2e_${randomBytes(4).toString("hex")}`
  const password = randomBytes(12).toString("base64url")
  const registered = await request.post("/api/v1/auth/register", {
    data: { username, email: `${username}@example.com`, password },
  })
  expect(registered.ok()).toBe(true)

  await page.goto("/login")
  await page.getByLabel("Username").fill(username)
  await page.getByLabel("Password").fill(password)
  await page.getByRole("button", { name: "Sign in" }).click()
  await expect(page.getByRole("heading", { name: /Welcome back/ })).toBeVisible()

  await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Events" }).click()
  await page.getByRole("button", { name: "Send test event" }).click()
  await page.getByRole("dialog").getByText("Editor opened").click()
  await page.getByRole("button", { name: "Send event" }).click()
  await expect(page.getByText("No threat detected")).toBeVisible()
})
