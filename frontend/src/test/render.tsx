import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { createMemoryRouter } from "react-router"
import { RouterProvider } from "react-router/dom"

import { routes } from "@/app/routes"
import { AuthProvider } from "@/auth/AuthProvider"
import { saveSession } from "@/auth/session"

import { fakeToken } from "./fixtures"

/** Render the whole app at a path, optionally with a signed-in session. */
export function renderApp(path: string, { signedIn = true } = {}) {
  if (signedIn) saveSession(fakeToken())
  const router = createMemoryRouter(routes, { initialEntries: [path] })
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const view = render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <RouterProvider router={router} />
      </AuthProvider>
    </QueryClientProvider>,
  )
  return { ...view, router, user: userEvent.setup() }
}
