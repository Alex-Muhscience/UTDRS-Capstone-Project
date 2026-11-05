// Apply the saved theme before first paint to avoid a flash. A file rather than an
// inline script, so the Content-Security-Policy can forbid inline scripts.
try {
  var theme = localStorage.getItem("utdrs-theme")
  if (theme === "light" || theme === "dark") document.documentElement.dataset.theme = theme
} catch (error) {
  // Storage blocked: the system theme applies.
}
