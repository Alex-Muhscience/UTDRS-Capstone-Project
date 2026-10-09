import "@testing-library/jest-dom/vitest"

import { cleanup } from "@testing-library/react"
import { afterEach, vi } from "vitest"

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  sessionStorage.clear()
  localStorage.clear()
})

// jsdom does not implement <dialog>'s modal methods.
HTMLDialogElement.prototype.showModal ??= function showModal(this: HTMLDialogElement) {
  this.open = true
}
HTMLDialogElement.prototype.close ??= function close(this: HTMLDialogElement) {
  this.open = false
  this.dispatchEvent(new Event("close"))
}
