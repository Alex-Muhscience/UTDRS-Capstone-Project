import { describe, expect, it } from "vitest"

import { deployedApiUrl } from "./deployment"

describe("the API gateway's address", () => {
  it("is the Render gateway on the Vercel deployment and its previews", () => {
    expect(deployedApiUrl("utdrs-capstone-project.vercel.app")).toBe("https://utdrs-api-gateway-1pjf.onrender.com")
    expect(deployedApiUrl("utdrs-capstone-project-4bv8011dv.vercel.app")).toBe("https://utdrs-api-gateway-1pjf.onrender.com")
    expect(deployedApiUrl("utdrs-capstone-project-git-main-team.vercel.app")).toBe("https://utdrs-api-gateway-1pjf.onrender.com")
  })

  it("is this origin anywhere else", () => {
    expect(deployedApiUrl("localhost")).toBe("")
    expect(deployedApiUrl("utdrs.example.com")).toBe("")
    expect(deployedApiUrl("utdrs-capstone-project.vercel.app.evil.example")).toBe("")
    expect(deployedApiUrl("other-project.vercel.app")).toBe("")
  })
})
