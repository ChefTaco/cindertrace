import type { z } from "zod";
import { localBrowserProfileSchema } from "@cindertrace/contracts";
export const useApiLocalAuth = () =>
  process.env.CINDERTRACE_API_BROWSER_AUTH === "true";
const Profile = localBrowserProfileSchema;
export async function apiLocalRequest(
  path: "login" | "session" | "logout",
  options: { token?: string; body?: string; all?: boolean } = {},
  request: typeof fetch = fetch,
): Promise<Response> {
  const target = new URL(
    process.env.CINDERTRACE_API_URL ?? process.env.CONTROL_API_URL ?? "",
  );
  const publicOrigin = new URL(process.env.DASHBOARD_PUBLIC_ORIGIN ?? "");
  if (
    target.protocol !== "https:" ||
    target.username ||
    target.password ||
    target.search ||
    target.hash ||
    target.pathname !== "/" ||
    publicOrigin.protocol !== "https:" ||
    publicOrigin.origin !== process.env.DASHBOARD_PUBLIC_ORIGIN
  )
    throw Error("Verified authentication API and browser origins are required");
  const headers = new Headers({
    "Content-Type": "application/json",
    Origin: publicOrigin.origin,
  });
  if (options.token) {
    if (!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(options.token))
      throw Error("Invalid browser cookie");
    headers.set("Cookie", "cindertrace_session=" + options.token);
  }
  return request(
    target.origin +
      "/api/v1/auth/local/" +
      path +
      (options.all ? "?all=true" : ""),
    {
      method: path === "session" ? "GET" : "POST",
      headers,
      ...(options.body === undefined ? {} : { body: options.body }),
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(12000),
    },
  );
}
export async function verifyApiLocalSession(
  token: string,
): Promise<z.infer<typeof Profile> | null> {
  const response = await apiLocalRequest("session", { token });
  if (response.status === 401) return null;
  if (!response.ok) throw Error("Browser session verification unavailable");
  return Profile.parse(await response.json());
}
export function forwardedSessionCookie(response: Response): string | undefined {
  const cookie = response.headers.get("set-cookie") ?? undefined;
  if (
    cookie &&
    (!cookie.startsWith("cindertrace_session=") ||
      /;\s*domain=/i.test(cookie) ||
      !cookie.includes("HttpOnly") ||
      !cookie.includes("Secure") ||
      !cookie.includes("SameSite=Lax"))
  )
    throw Error("Invalid API session cookie");
  return cookie;
}
