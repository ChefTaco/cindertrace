import { jwtVerify } from "jose";
import { matchesSha256Digest, timingSafeEqualString } from "@hivemagnus/hive-common/secrets";
import type { Context, Next } from "hono";
import type {
  AppVariables,
  AuthTokenPayload,
  UserRole,
  SecurityPermission,
} from "../types/index.js";
import { HttpError } from "./error-handler.js";
import { oathweaveAuthentication } from './oathweave.js';
import { getCookie } from 'hono/cookie';
import { browserAuthEnabled, browserSessions, COOKIE_NAME } from '../browser-auth/sessions.js';
import { exactBrowserOrigin } from '../browser-auth/origin.js';
import { setting } from '../config/settings.js';
let digestCache: { raw: string; value: Record<string, string> } | undefined;
/**
 * The named read-credential digests in SECURITY_PLUGIN_READ_DIGESTS_JSON: a JSON object of
 * name to lowercase-hex SHA-256 digest. Startup validation refuses anything else, so a bad
 * value stops the API instead of failing every request.
 */
export function pluginReadDigests(env: NodeJS.ProcessEnv = process.env): Record<string, string> {
  const raw = env["SECURITY_PLUGIN_READ_DIGESTS_JSON"] ?? "{}";
  if (digestCache?.raw === raw) return digestCache.value;
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error("SECURITY_PLUGIN_READ_DIGESTS_JSON is not valid JSON");
  }
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("SECURITY_PLUGIN_READ_DIGESTS_JSON must be an object of name to SHA-256 digest");
  for (const [name, digest] of Object.entries(value))
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(name) || typeof digest !== "string" || !/^[a-f0-9]{64}$/.test(digest))
      throw new Error("SECURITY_PLUGIN_READ_DIGESTS_JSON must map credential names to lowercase-hex SHA-256 digests");
  digestCache = { raw, value: value as Record<string, string> };
  return digestCache.value;
}
/** Constant-time string equality; strings of different byte length are unequal. */
export function safeEqual(a: string, b: string): boolean {
  return timingSafeEqualString(a, b);
}
/** Whether `token` hashes to the stored lowercase-hex SHA-256 digest. An empty token or unset digest never matches. */
export function tokenMatches(
  token: string,
  digest: string | undefined,
): boolean {
  return matchesSha256Digest(token, digest);
}
/**
 * Short-lived HS256 bearers for the in-process test suites only (`scripts/test-bearer.mjs`).
 * They are honoured only while CINDERTRACE_TEST_BEARER_SECRET is set, and the API server
 * refuses to start with it set, so a running installation never accepts them. They replace
 * the retired console's `SECURITY_CONSOLE_TOKEN_SECRET` tokens.
 */
async function testBearer(token: string): Promise<AuthTokenPayload> {
  const secret = process.env["CINDERTRACE_TEST_BEARER_SECRET"];
  if (!secret || secret.length < 32) throw new Error("test bearers disabled");
  const { payload } = await jwtVerify(token, new TextEncoder().encode(secret), {
    algorithms: ["HS256"],
    issuer: "cindertrace-test",
    audience: "cindertrace-api",
    maxTokenAge: "180s",
  });
  if (
    typeof payload["userId"] !== "string" ||
    !["ADMIN", "OPERATOR", "VIEWER"].includes(String(payload["role"]))
  )
    throw new Error("invalid identity");
  return payload as unknown as AuthTokenPayload;
}
export async function authMiddleware(c: Context<AppVariables>, next: Next) {
  const token = c.req.header("Authorization")?.replace(/^Bearer /, "") ?? "";
  if (!token && browserAuthEnabled() && getCookie(c, COOKIE_NAME)) {
    if (!['GET', 'HEAD'].includes(c.req.method) && !exactBrowserOrigin(c.req.header('Origin')))
      throw new HttpError(403, 'FORBIDDEN', 'Exact browser origin required');
    let session;
    try {session=await (await browserSessions()).verify(getCookie(c, COOKIE_NAME)!);}
    catch {throw new HttpError(503,'AUTH_UNAVAILABLE','Browser session verification is unavailable');}
    if(!session)throw new HttpError(401,'UNAUTHORIZED','Invalid or revoked browser session');
    c.set('user',{userId:session.userId??setting(process.env,'CINDERTRACE_ADMIN_ACCOUNT_ID')??session.username,email:'',role:session.role,iat:session.iat,exp:session.exp});
    await next(); return;
  }
  const read = Object.entries(pluginReadDigests()).find(([, digest]) =>
    tokenMatches(token, digest),
  );
  const draft = tokenMatches(
    token,
    process.env["SECURITY_PLUGIN_DRAFT_TOKEN_SHA256"],
  );
  const labControl = tokenMatches(token, process.env["SECURITY_PLUGIN_LAB_CONTROL_TOKEN_SHA256"]);
  const workflow = tokenMatches(token, process.env["SECURITY_PLUGIN_WORKFLOW_TOKEN_SHA256"]);
  const sentiBridge = tokenMatches(token, process.env["SECURITY_EXTERNAL_APPROVAL_TOKEN_SHA256"] ?? process.env["SECURITY_SENTI_BRIDGE_TOKEN_SHA256"]);
  if (read || draft || workflow || sentiBridge || labControl) {
    const path = c.req.path.replace("/api/v1/security-fusion", "");
    const allowed = labControl
      ? process.env["CINDERTRACE_LAB_ENABLED"] === "true" && c.req.method === "POST" && /^\/lab\/runs\/[^/]+\/(advance|complete)$/.test(path)
      : sentiBridge
      ? (c.req.method === "GET" && (path === "/approval-plans" || /^\/approval-plans\/[^/]+$/.test(path)))
        || (c.req.method === "POST" && path === "/approval-decisions")
      : read
      ? (c.req.method === "POST" && /^\/cases\/[^/]+\/assurance\/exposure\/preview$/.test(path)) ||
        (c.req.method === "GET" &&
        (path === "/lab" || /^\/lab\/runs\/[^/]+(?:\/comparison)?$/.test(path) || path === "/sources" ||
          /^\/(overview|cases|events|entities)(\/[^/]+)?$/.test(path)))
      : draft ? c.req.method === "POST" &&
        /^\/cases\/[^/]+\/investigations$/.test(path)
      : (c.req.method === "PATCH" && /^\/cases\/[^/]+$/.test(path)) ||
        (c.req.method === "POST" && (
          /^\/cases\/[^/]+\/evidence\/[^/]+\/preserve$/.test(path) ||
          /^\/cases\/[^/]+\/assurance\/(exposure|investigation|review|closure)$/.test(path) ||
          /^\/cases\/[^/]+\/actions\/preview$/.test(path) ||
          /^\/actions\/[^/]+\/(request|cancel)$/.test(path)));
    if (!allowed)
      throw new HttpError(
        403,
        "FORBIDDEN",
        "Service credential is endpoint-scoped",
      );
    c.set("user", {
      userId: sentiBridge ? "service:senti-approval-bridge"
        : `service:security-plugin:${read?.[0] ?? (draft ? "draft" : labControl ? "lab-control" : "aegis-workflow")}`,
      email: "",
      role: "OPERATOR",
      iat: 0,
      exp: 0,
    });
  } else {
    let identity: AuthTokenPayload | undefined;
    try { identity = await oathweaveAuthentication(token); }
    catch { throw new HttpError(401, 'UNAUTHORIZED', 'Invalid or unlinked identity session'); }
    if (identity) { c.set('user',identity); await next(); return; }
    try {
      c.set("user", await testBearer(token));
    } catch {
      throw new HttpError(
        401,
        "UNAUTHORIZED",
        "Invalid or expired security token",
      );
    }
  }
  await next();
}
export function getUser(c: Context<AppVariables>): AuthTokenPayload {
  if (!c.var.user)
    throw new HttpError(401, "UNAUTHORIZED", "Not authenticated");
  return c.var.user;
}
export function requireRole(...roles: UserRole[]) {
  return async (c: Context<AppVariables>, next: Next) => {
    if (!roles.includes(getUser(c).role))
      throw new HttpError(403, "FORBIDDEN", "Role does not permit this action");
    await next();
  };
}
/**
 * ADMIN holds every permission; OPERATOR reads cases, events and entities; VIEWER sees only
 * the summary (overview counts, source health, retention policy). Evidence stays ADMIN-only.
 */
export function hasPermission(
  user: AuthTokenPayload,
  permission: SecurityPermission,
): boolean {
  return (
    user.role === "ADMIN" ||
    permission === "security-fusion:summary" ||
    (user.role === "OPERATOR" && permission === "security-fusion:read")
  );
}
export function requirePermission(permission: SecurityPermission) {
  return async (c: Context<AppVariables>, next: Next) => {
    if (!hasPermission(getUser(c), permission))
      throw new HttpError(403, "FORBIDDEN", "Permission required");
    await next();
  };
}
