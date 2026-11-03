import { createHash, timingSafeEqual } from "node:crypto";
import { jwtVerify } from "jose";
import type { Context, Next } from "hono";
import type {
  AppVariables,
  AuthTokenPayload,
  UserRole,
  SecurityPermission,
} from "../types/index.js";
import { HttpError } from "./error-handler.js";
export function safeEqual(a: string, b: string): boolean {
  const aa = Buffer.from(a),
    bb = Buffer.from(b);
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}
export function tokenMatches(
  token: string,
  digest: string | undefined,
): boolean {
  return Boolean(
    token &&
      digest &&
      safeEqual(createHash("sha256").update(token).digest("hex"), digest),
  );
}
export async function authMiddleware(c: Context<AppVariables>, next: Next) {
  const token = c.req.header("Authorization")?.replace(/^Bearer /, "") ?? "";
  const registry = JSON.parse(
    process.env["SECURITY_PLUGIN_READ_DIGESTS_JSON"] ?? "{}",
  ) as Record<string, string>;
  const read = Object.entries(registry).find(([, digest]) =>
    tokenMatches(token, digest),
  );
  const draft = tokenMatches(
    token,
    process.env["SECURITY_PLUGIN_DRAFT_TOKEN_SHA256"],
  );
  const workflow = tokenMatches(token, process.env["SECURITY_PLUGIN_WORKFLOW_TOKEN_SHA256"]);
  const sentiBridge = tokenMatches(token, process.env["SECURITY_EXTERNAL_APPROVAL_TOKEN_SHA256"] ?? process.env["SECURITY_SENTI_BRIDGE_TOKEN_SHA256"]);
  if (read || draft || workflow || sentiBridge) {
    const path = c.req.path.replace("/api/v1/security-fusion", "");
    const allowed = sentiBridge
      ? (c.req.method === "GET" && (path === "/approval-plans" || /^\/approval-plans\/[^/]+$/.test(path)))
        || (c.req.method === "POST" && path === "/approval-decisions")
      : read
      ? (c.req.method === "POST" && /^\/cases\/[^/]+\/assurance\/exposure\/preview$/.test(path)) ||
        (c.req.method === "GET" &&
        (path === "/sources" ||
          /^\/(overview|cases|events|entities|evidence)(\/[^/]+)?$/.test(path)))
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
        : `service:security-plugin:${read?.[0] ?? (draft ? "draft" : "aegis-workflow")}`,
      email: "",
      role: "OPERATOR",
      iat: 0,
      exp: 0,
    });
  } else {
    try {
      const secret = process.env["SECURITY_CONSOLE_TOKEN_SECRET"];
      if (!secret || secret.length < 32) throw new Error("missing secret");
      const { payload } = await jwtVerify(
        token,
        new TextEncoder().encode(secret),
        {
          algorithms: ["HS256"],
          issuer: "cindertrace-console",
          audience: "cindertrace-api",
          maxTokenAge: "60s",
        },
      );
      if (
        typeof payload["userId"] !== "string" ||
        !["ADMIN", "OPERATOR", "VIEWER"].includes(String(payload["role"]))
      )
        throw new Error("invalid identity");
      c.set("user", payload as unknown as AuthTokenPayload);
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
export function hasPermission(
  user: AuthTokenPayload,
  permission: SecurityPermission,
): boolean {
  return (
    user.role === "ADMIN" ||
    (user.role === "OPERATOR" &&
      permission === "security-fusion:read")
  );
}
export function requirePermission(permission: SecurityPermission) {
  return async (c: Context<AppVariables>, next: Next) => {
    if (!hasPermission(getUser(c), permission))
      throw new HttpError(403, "FORBIDDEN", "Permission required");
    await next();
  };
}
