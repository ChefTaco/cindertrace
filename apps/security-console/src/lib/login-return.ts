/** Operator-owned same-origin landing path; never read redirect targets from a request. */
export function configuredLoginReturnURL(): URL {
  const origin = new URL(process.env.DASHBOARD_PUBLIC_ORIGIN ?? "");
  if (
    origin.protocol !== "https:" ||
    origin.username ||
    origin.password ||
    origin.pathname !== "/" ||
    origin.search ||
    origin.hash
  ) {
    throw new Error("Exact HTTPS dashboard origin required");
  }

  const path = process.env.DASHBOARD_LOGIN_RETURN_PATH ?? "/";
  // Literal path segments keep browsers and ingress from disagreeing about
  // encoded separators, backslashes, dot traversal, queries or fragments.
  if (
    path.length > 2048 ||
    !/^\/(?:[A-Za-z0-9._~-]+(?:\/[A-Za-z0-9._~-]+)*\/?)?$/.test(path) ||
    path.split("/").some((segment) => segment === "." || segment === "..")
  ) {
    throw new Error("Dashboard login return path must be a literal absolute path");
  }
  const target = new URL(path, origin.origin);
  if (target.origin !== origin.origin || target.pathname !== path) {
    throw new Error("Dashboard login return path must retain the dashboard origin");
  }
  return target;
}
