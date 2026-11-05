/** Browser mutations accept only the configured HTTPS origin, never forwarded headers. */
export function exactBrowserOrigin(
  origin: string | undefined,
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  try {
    const configured = new URL(env.DASHBOARD_PUBLIC_ORIGIN ?? "");
    return (
      configured.protocol === "https:" &&
      !configured.username &&
      !configured.password &&
      !configured.search &&
      !configured.hash &&
      configured.pathname === "/" &&
      origin === configured.origin
    );
  } catch {
    return false;
  }
}
