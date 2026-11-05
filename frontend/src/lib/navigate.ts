/** Leave the dashboard for another site, such as an identity provider's sign-in page. */
export function leaveFor(url: string): void {
  window.location.assign(url)
}
