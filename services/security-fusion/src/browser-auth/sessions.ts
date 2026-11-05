import { createHmac, randomUUID } from "node:crypto";
import { Redis } from "ioredis";
import { SignJWT, jwtVerify } from "jose";
import { z } from "zod";
import { credentials } from "./credentials.js";

export const COOKIE_NAME = "cindertrace_session",
  SESSION_DURATION = 86400;
const Session = z.object({
  username: z.string().min(1).max(256),
  sessionId: z.string().uuid(),
  userId: z.string().optional(),
  role: z.enum(["ADMIN", "OPERATOR", "VIEWER"]).default("ADMIN"),
  provider: z.literal("hive").optional(),
  iat: z.number(),
  exp: z.number(),
});
export type BrowserSession = z.infer<typeof Session>;
export type SessionStore = Pick<Redis, "eval" | "mget" | "set" | "del">;
// Same atomic limit, expiry clock and keys as runtime-local-sessions.mjs. Existing
// session and revocation records are adopted in place, never reseeded or merged.
const CREATE = `
local generation = redis.call('GET', KEYS[1]) or ARGV[1]
redis.call('SET', KEYS[1], generation, 'EX', ARGV[4])
local time = redis.call('TIME')
local now = time[1] * 1000000 + time[2]
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)
local oldest = redis.call('ZRANGE', KEYS[2], 0, -50)
for _, id in ipairs(oldest) do redis.call('DEL', ARGV[6] .. id); redis.call('ZREM', KEYS[2], id) end
redis.call('ZADD', KEYS[2], now + ARGV[4] * 1000000, ARGV[2])
redis.call('EXPIRE', KEYS[2], ARGV[4])
redis.call('SET', KEYS[3], generation .. ':' .. ARGV[3], 'EX', ARGV[4])
return generation
`;
export function browserSessionSecret(
  env: NodeJS.ProcessEnv = process.env,
): Uint8Array {
  const secret = env.SESSION_SECRET;
  if (!secret || secret.length < 32)
    throw Error("Dedicated browser session secret is required");
  return new TextEncoder().encode(secret);
}
export class BrowserSessions {
  constructor(
    readonly store: SessionStore,
    readonly env: NodeJS.ProcessEnv = process.env,
  ) {}
  secret(): Uint8Array {
    return browserSessionSecret(this.env);
  }
  key(username: string): string {
    return `${COOKIE_NAME}:local:${createHmac("sha256", this.secret()).update(username).digest("hex")}`;
  }
  credentialGeneration(): string {
    const value = credentials(this.env);
    return createHmac("sha256", this.secret())
      .update(
        JSON.stringify([
          value.username,
          value.passwordHash ?? value.password,
          this.env.LOCAL_SESSION_GENERATION ?? "",
        ]),
      )
      .digest("hex");
  }
  async create(username: string): Promise<string> {
    const id = randomUUID(),
      key = this.key(username);
    await this.store.eval(
      CREATE,
      3,
      `${key}:generation`,
      `${key}:sessions`,
      `${key}:session:${id}`,
      randomUUID(),
      id,
      this.credentialGeneration(),
      SESSION_DURATION,
      Math.floor(Date.now() / 1000),
      `${key}:session:`,
    );
    return new SignJWT({
      username,
      sessionId: id,
      role: "ADMIN",
      userId: this.env.DASHBOARD_ADMIN_ACCOUNT_ID ?? username,
    })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuer(this.env.SESSION_ISSUER?.trim() || "cindertrace-console")
      .setAudience(this.env.SESSION_AUDIENCE?.trim() || "cindertrace-console")
      .setIssuedAt()
      .setExpirationTime(`${SESSION_DURATION}s`)
      .sign(this.secret());
  }
  async verify(token: string): Promise<BrowserSession | null> {
    let session: BrowserSession;
    try {
      const { payload } = await jwtVerify(token, this.secret(), {
        algorithms: ["HS256"],
        issuer: this.env.SESSION_ISSUER?.trim() || "cindertrace-console",
        audience: this.env.SESSION_AUDIENCE?.trim() || "cindertrace-console",
      });
      session = Session.parse(payload);
    } catch {
      return null;
    }
    // Legacy console OAuth sessions have an independent encrypted credential
    // store. They remain on their compatibility path until explicitly migrated.
    if (session.provider || session.username !== credentials(this.env).username)
      return null;
    const key = this.key(session.username);
    const [generation, record] = await this.store.mget(
      `${key}:generation`,
      `${key}:session:${session.sessionId}`,
    );
    return generation &&
      record === `${generation}:${this.credentialGeneration()}`
      ? session
      : null;
  }
  async revoke(session: BrowserSession, all = false): Promise<void> {
    const key = this.key(session.username);
    if (all)
      await this.store.set(
        `${key}:generation`,
        randomUUID(),
        "EX",
        SESSION_DURATION,
      );
    else await this.store.del(`${key}:session:${session.sessionId}`);
  }
}
let sessions: BrowserSessions | undefined;
export function browserAuthEnabled(
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  return env.CINDERTRACE_BROWSER_AUTH_ENABLED === "true";
}
export async function browserSessions(): Promise<BrowserSessions> {
  if (!sessions) {
    if (!process.env.REDIS_URL)
      throw Error("Browser session storage is not configured");
    const redis = new Redis(process.env.REDIS_URL, {
      lazyConnect: true,
      maxRetriesPerRequest: 1,
      connectTimeout: 2000,
      commandTimeout: 2500,
      enableOfflineQueue: false,
    });
    redis.on("error", () => undefined);
    sessions = new BrowserSessions(redis);
  }
  const redis = sessions.store as Redis;
  if (redis.status === "wait") await redis.connect();
  if (redis.status !== "ready")
    throw Error("Browser session storage is unavailable");
  return sessions;
}
