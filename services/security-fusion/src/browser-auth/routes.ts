import { appendBrowserSecurityEvent } from "./security-events.js";
import { boundedLoginBody } from "./body.js";
import { Hono, type Context } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { z } from "zod";
import { localBrowserLoginSchema } from "@cindertrace/contracts";
import type { AppVariables } from "../types/index.js";
import { getConnInfo } from "@hono/node-server/conninfo";
import { exactBrowserOrigin } from "./origin.js";
import { logAuditEvent } from "../services/audit-service.js";
import { beginAuthentication } from "./throttling.js";
import { validateLocalCredentials } from "./credentials.js";
import {
  BrowserSessions,
  browserSessions,
  browserAuthEnabled,
  COOKIE_NAME,
  SESSION_DURATION,
} from "./sessions.js";

const Login = localBrowserLoginSchema;
function peerAddress(c: Context<AppVariables>): string {
  try {
    return getConnInfo(c).remote.address ?? "unverified";
  } catch {
    return "unverified";
  }
}
type Admission = Awaited<ReturnType<typeof beginAuthentication>>;
type Dependencies = {
  env?: NodeJS.ProcessEnv;
  sessions?: () => Promise<BrowserSessions>;
  admission?: typeof beginAuthentication;
  audit?: (
    action: string,
    actorId: string,
    details: Record<string, unknown>,
    ipAddress?: string,
    username?: string,
  ) => Promise<void>;
};
export function browserAuthRouter(
  dependencies: Dependencies = {},
): Hono<AppVariables> {
  const router = new Hono<AppVariables>(),
    env = dependencies.env ?? process.env;
  const sessions = dependencies.sessions ?? browserSessions,
    admission = dependencies.admission ?? beginAuthentication;
  const audit: NonNullable<Dependencies["audit"]> =
    dependencies.audit ??
    (async (action, actorId, details, ipAddress, username) => {
      await logAuditEvent({
        action,
        actorId,
        ipAddress,
        targetType: "browser-session",
        targetId: actorId,
        details,
      });
      await appendBrowserSecurityEvent(
        action,
        ipAddress ?? "unverified",
        username ?? "",
        env,
      );
    });

  router.use("*", async (c, next) => {
    if (!browserAuthEnabled(env))
      return c.json({ error: "Browser authentication is not configured" }, 404);
    c.header("Cache-Control", "no-store");
    if (
      !["GET", "HEAD"].includes(c.req.method) &&
      !exactBrowserOrigin(c.req.header("Origin"), env)
    )
      return c.json({ error: "Exact browser origin required" }, 403);
    return next();
  });
  router.post("/login", async (c) => {
    let permit: Admission | undefined;
    try {
      let raw: string;
      try {
        raw = await boundedLoginBody(c.req.raw);
      } catch {
        return c.json({ error: "Request too large" }, 413);
      }
      let body: z.infer<typeof Login>;
      try {
        body = Login.parse(JSON.parse(raw));
      } catch {
        return c.json({ error: "Invalid authentication request" }, 400);
      }
      // Node peer wins over all caller-supplied forwarding headers.
      const source = peerAddress(c);
      permit = await admission(source, body.username);
      const labels = {
        source: permit.sourceLabel,
        username: permit.usernameLabel,
        pair: permit.pairLabel,
      };
      if (!permit.allowed) {
        await audit(
          "auth.login_throttled",
          "anonymous",
          labels,
          source,
          body.username,
        );
        c.header("Retry-After", String(permit.retryAfterSeconds));
        return c.json({ error: "Too many login attempts" }, 429);
      }
      if (
        !(await validateLocalCredentials(body.username, body.password, env))
      ) {
        await audit(
          "auth.login_failed",
          "anonymous",
          labels,
          source,
          body.username,
        );
        return c.json({ error: "Invalid credentials" }, 401);
      }
      const token = await (await sessions()).create(body.username),
        actorId = env.DASHBOARD_ADMIN_ACCOUNT_ID ?? body.username;
      await audit(
        "auth.login_succeeded",
        actorId,
        labels,
        source,
        body.username,
      );
      await permit.clearSuccessfulPair();
      setCookie(c, COOKIE_NAME, token, {
        httpOnly: true,
        secure: true,
        sameSite: "Lax",
        path: "/",
        maxAge: SESSION_DURATION,
      });
      return c.json({
        ok: true,
        username: body.username,
        userId: actorId,
        role: "ADMIN",
      });
    } catch {
      await audit(
        "auth.login_error",
        "anonymous",
        { reason: "authentication_unavailable" },
        peerAddress(c),
      ).catch(() => undefined);
      return c.json({ error: "Authentication temporarily unavailable" }, 503);
    } finally {
      await permit?.release().catch(() => undefined); // Redis lease expiry is the final safety net.
    }
  });
  router.get("/session", async (c) => {
    try {
      const session = await (
        await sessions()
      ).verify(getCookie(c, COOKIE_NAME) ?? "");
      if (!session) return c.json({ error: "Authentication required" }, 401);
      return c.json({
        username: session.username,
        userId:
          session.userId ?? env.DASHBOARD_ADMIN_ACCOUNT_ID ?? session.username,
        role: session.role,
        provider: session.provider === "oathweave" ? "oathweave" : "local",
      });
    } catch {
      return c.json({ error: "Session verification unavailable" }, 503);
    }
  });
  router.post("/logout", async (c) => {
    try {
      const service = await sessions(),
        session = await service.verify(getCookie(c, COOKIE_NAME) ?? "", false);
      if (session) {
        await service.revoke(session, c.req.query("all") === "true");
        await audit(
          "auth.logout",
          session.userId ?? env.DASHBOARD_ADMIN_ACCOUNT_ID ?? session.username,
          { all: c.req.query("all") === "true" },
          peerAddress(c),
          session.username,
        );
      }
      setCookie(c, COOKIE_NAME, "", {
        httpOnly: true,
        secure: true,
        sameSite: "Lax",
        path: "/",
        maxAge: 0,
      });
      return c.json({ ok: true });
    } catch {
      return c.json(
        { error: "Session revocation unavailable; retry sign out" },
        503,
      );
    }
  });
  return router;
}
