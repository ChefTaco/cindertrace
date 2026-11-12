import { createHmac, randomUUID, randomBytes, createCipheriv, createDecipheriv, createHash } from "node:crypto";
import { Redis } from "ioredis";
import { SignJWT, jwtVerify } from "jose";
import { z } from "zod";
import { configuredOathweaveVerifier, linkedSecurityIdentity, type OathweaveIdentity } from "../middleware/oathweave.js";
import { credentials } from "./credentials.js";

export const COOKIE_NAME = "cindertrace_session",
  SESSION_DURATION = 86400;
const Session = z.object({
  username: z.string().min(1).max(256),
  sessionId: z.string().uuid(),
  userId: z.string().optional(),
  role: z.enum(["ADMIN", "OPERATOR", "VIEWER"]).default("ADMIN"),
  provider: z.enum(["hive", "oathweave"]).optional(),
  identityIssuer: z.string().optional(),
  subject: z.string().optional(),
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
// Resource sessions have different expiries. Shared generations/indexes must
// outlive every still-valid member, while each credential keeps its own expiry.
const CREATE_OATHWEAVE = `
local generation = redis.call('GET', KEYS[1]) or ARGV[1]
local sharedTTL = math.max(tonumber(ARGV[4]), redis.call('TTL', KEYS[1]), redis.call('TTL', KEYS[2]))
redis.call('SET', KEYS[1], generation, 'EX', sharedTTL)
local time = redis.call('TIME')
local now = time[1] * 1000000 + time[2]
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)
local oldest = redis.call('ZRANGE', KEYS[2], 0, -50)
for _, id in ipairs(oldest) do redis.call('DEL', ARGV[6] .. id); redis.call('ZREM', KEYS[2], id) end
redis.call('ZADD', KEYS[2], now + ARGV[4] * 1000000, ARGV[2])
redis.call('EXPIRE', KEYS[2], sharedTTL)
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
    readonly verifyIdentity: (token:string)=>Promise<OathweaveIdentity> = async token => {
      const verify=configuredOathweaveVerifier();if(!verify)throw Error("Oathweave integration unavailable");return verify(token);
    },
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
  oathweaveKey(issuer: string, subject: string): string {
    return `${COOKIE_NAME}:oathweave:${createHmac("sha256",this.secret()).update(JSON.stringify([issuer,subject])).digest("hex")}`;
  }
  credentialCipherKey(): Buffer { return createHash("sha256").update("cindertrace:api:oathweave:v1\0").update(this.secret()).digest(); }
  sealCredential(token: string,id:string): string {
    const iv=randomBytes(12),cipher=createCipheriv("aes-256-gcm",this.credentialCipherKey(),iv);cipher.setAAD(Buffer.from(id));
    const bytes=Buffer.concat([cipher.update(token,"utf8"),cipher.final()]);return Buffer.concat([iv,cipher.getAuthTag(),bytes]).toString("base64url");
  }
  openCredential(value:string,id:string): string {
    const bytes=Buffer.from(value,"base64url"),cipher=createDecipheriv("aes-256-gcm",this.credentialCipherKey(),bytes.subarray(0,12));cipher.setAAD(Buffer.from(id));cipher.setAuthTag(bytes.subarray(12,28));return Buffer.concat([cipher.update(bytes.subarray(28)),cipher.final()]).toString("utf8");
  }
  async createOathweave(token:string): Promise<{token:string;ttl:number}> {
    const identity=await this.verifyIdentity(token),linked=linkedSecurityIdentity(identity,this.env.CINDERTRACE_OATHWEAVE_IDENTITIES_JSON);
    const ttl=Math.min(900,Math.floor((identity.expiresAt??0)-Date.now()/1000));if(ttl<1)throw Error("Resource identity expired");
    const id=randomUUID(),key=this.oathweaveKey(identity.issuer,identity.subject);
    await this.store.eval(CREATE_OATHWEAVE,3,`${key}:generation`,`${key}:sessions`,`${key}:session:${id}`,randomUUID(),id,this.sealCredential(token,id),ttl,Math.floor(Date.now()/1000),`${key}:session:`);
    return {ttl,token:await new SignJWT({username:identity.displayName,userId:linked.userId,role:linked.role,provider:"oathweave",identityIssuer:identity.issuer,subject:identity.subject,sessionId:id}).setProtectedHeader({alg:"HS256"}).setIssuer(this.env.SESSION_ISSUER?.trim()||"cindertrace-console").setAudience(this.env.SESSION_AUDIENCE?.trim()||"cindertrace-console").setIssuedAt().setExpirationTime(`${ttl}s`).sign(this.secret())};
  }
  async verify(token: string, checkIdentity = true): Promise<BrowserSession | null> {
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
    if(session.provider==="oathweave") {
      if(!session.identityIssuer||!session.subject||!session.userId)return null;
      const key=this.oathweaveKey(session.identityIssuer,session.subject),[generation,record]=await this.store.mget(`${key}:generation`,`${key}:session:${session.sessionId}`);
      if(!generation||!record?.startsWith(generation+":"))return null;
      // Logout must durably revoke the local record even while the identity service is unavailable.
      if(!checkIdentity)return session;
      try {
        const identity=await this.verifyIdentity(this.openCredential(record.slice(generation.length+1),session.sessionId));
        if(identity.issuer!==session.identityIssuer||identity.subject!==session.subject)return null;
        const linked=linkedSecurityIdentity(identity,this.env.CINDERTRACE_OATHWEAVE_IDENTITIES_JSON);if(linked.userId!==session.userId)return null;
        return {...session,role:linked.role};
      } catch {return null;}
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
    const key = session.provider==="oathweave"?this.oathweaveKey(session.identityIssuer!,session.subject!):this.key(session.username);
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
