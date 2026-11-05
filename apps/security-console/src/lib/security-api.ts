import {useApiLocalAuth} from "./api-local-auth";
import "server-only";
import { cookies } from "next/headers";
import { SignJWT } from "jose";
import { verifySessionToken, COOKIE_NAME } from "./auth";
import { hiveCredential } from "./hive-login";
export async function securityRequest(path: string, init: RequestInit = {}) {
  if (
    !/^security-fusion\//.test(path) ||
    path.includes("..") ||
    path.includes("\\")
  )
    throw new Error("Invalid security API path");
  const session = await verifySessionToken(
    (await cookies()).get(COOKIE_NAME)?.value ?? "",
  );
  if (!session) throw new Error("Authentication required");
  if (session.provider === "hive")
    await hiveCredential(session, (process.env["CINDERTRACE_API_URL"] ?? process.env["CONTROL_API_URL"])!);
  if(useApiLocalAuth()&&session.provider!=="hive"){
    const origin=new URL((process.env["CINDERTRACE_API_URL"]??process.env["CONTROL_API_URL"])!);
    if(origin.protocol!=="https:"||origin.username||origin.password||origin.pathname!=="/"||origin.search||origin.hash)throw Error("Verified API origin required");
    return fetch(`${origin.origin}/api/v1/${path}`,{...init,headers:{"Content-Type":"application/json",Cookie:`${COOKIE_NAME}=${(await cookies()).get(COOKIE_NAME)!.value}`,Origin:process.env["DASHBOARD_PUBLIC_ORIGIN"]!},cache:"no-store",redirect:"error",signal:AbortSignal.timeout(20000)});
  }
  const secret = process.env["SECURITY_CONSOLE_TOKEN_SECRET"];
  if (!secret || secret.length < 32)
    throw new Error("Security API credential unavailable");
  const token = await new SignJWT({
    userId: session.userId ?? session.username,
    email: session.email ?? "",
    role: session.role ?? "ADMIN",
  })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer("cindertrace-console")
    .setAudience("cindertrace-api")
    .setIssuedAt()
    .setExpirationTime("60s")
    .sign(new TextEncoder().encode(secret));
  const origin = new URL((process.env["CINDERTRACE_API_URL"] ?? process.env["CONTROL_API_URL"])!);
  if (origin.protocol !== "https:") throw new Error("TLS required");
  return fetch(`${origin.origin}/api/v1/${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(20000),
  });
}
export async function securityFetch<T>(path: string): Promise<T> {
  const res = await securityRequest(path);
  if (!res.ok) throw new Error(`Security API HTTP ${res.status}`);
  return res.json() as Promise<T>;
}
