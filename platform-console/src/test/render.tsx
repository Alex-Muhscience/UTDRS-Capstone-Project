import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { createMemoryRouter } from "react-router"
import { RouterProvider } from "react-router/dom"
import { Toaster } from "sonner"

import { startSession } from "@/api/client"
import { routes } from "@/routes"

/** The whole console at a path, optionally signed in. */
export function renderConsole(path: string, { signedIn = true } = {}) {
  if (signedIn) startSession("operator-token", 600)
  const router = createMemoryRouter(routes, { initialEntries: [path] })
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const view = render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
      <Toaster />
    </QueryClientProvider>,
  )
  return { ...view, router, user: userEvent.setup() }
}
