import { isRouteErrorResponse, useRouteError } from "react-router"

import { buttonClasses } from "@/components/ui/buttonClasses"

/** Last-resort error screen for errors thrown while rendering a route. */
export function RouteError() {
  const error = useRouteError()
  const message = isRouteErrorResponse(error)
    ? `${error.status} ${error.statusText}`
    : error instanceof Error
      ? error.message
      : "Unexpected error"

  return (
    <div className="grid min-h-dvh place-items-center p-6 text-center">
      <div className="max-w-md">
        <h1 className="text-lg font-semibold">Something went wrong</h1>
        <p className="mt-2 text-sm break-words text-muted">{message}</p>
        {/* A full reload, so a broken render state is not reused. */}
        <a href="/" className={buttonClasses("primary", "md", "mt-6")}>
          Reload the dashboard
        </a>
      </div>
    </div>
  )
}
