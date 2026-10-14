import { QueryClientProvider } from "@tanstack/react-query"
import { Analytics } from "@vercel/analytics/react"
import { useState } from "react"
import { createBrowserRouter } from "react-router"
import { RouterProvider } from "react-router/dom"
import { Toaster } from "sonner"

import { AuthProvider } from "@/auth/AuthProvider"

import { createQueryClient } from "./queryClient"
import { routes } from "./routes"

const router = createBrowserRouter(routes)

export function App() {
  const [queryClient] = useState(createQueryClient)
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <RouterProvider router={router} />
        <Toaster
          position="bottom-right"
          toastOptions={{
            className: "!bg-surface !text-fg !border-border",
          }}
        />
      </AuthProvider>
      <Analytics />
    </QueryClientProvider>
  )
}
