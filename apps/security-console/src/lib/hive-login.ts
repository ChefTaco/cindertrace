import {
  createHash,
  randomBytes,
  createCipheriv,
  createDecipheriv,
} from "node:crypto";
import { createRemoteJWKSet, customFetch, jwtVerify } from "jose";
import { Redis } from "ioredis";
import { getSecretKey } from "./auth-constants";
import type { SessionPayload } from "./auth";

export interface HiveLoginSession {
  username: string;
  userId: string;
  role: "ADMIN" | "OPERATOR" | "VIEWER";
  provider: "hive";
  sessionId: string;
  ttl: number;
}

type HiveSessionReference = Pick<
  SessionPayload,
  "provider" | "sessionId" | "userId"
>;

let client: Redis | undefined;
function redis() {
  if (!client) {
    client = new Redis(process.env["REDIS_URL"] ?? "redis://127.0.0.1:6379", {
      maxRetriesPerRequest: 1,
      enableOfflineQueue: false,
      lazyConnect: true,
    });
    client.on("error", () => undefined);
  }
  return client;
}
async function store() {
  const r = redis();
  if (r.status === "wait") await r.connect();
  return r;
}
const key = () =>
  createHash("sha256")
    .update("cindertrace:hive-session:v1\0")
    .update(getSecretKey())
    .digest();
function seal(value: unknown, id: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key(), iv);
  cipher.setAAD(Buffer.from(id));
  const data = Buffer.concat([
    cipher.update(JSON.stringify(value)),
    cipher.final(),
  ]);
  return Buffer.concat([iv, cipher.getAuthTag(), data]).toString("base64url");
}
function open(value: string, id: string) {
  const data = Buffer.from(value, "base64url");
  const cipher = createDecipheriv("aes-256-gcm", key(), data.subarray(0, 12));
  cipher.setAAD(Buffer.from(id));
  cipher.setAuthTag(data.subarray(12, 28));
  return JSON.parse(
    Buffer.concat([cipher.update(data.subarray(28)), cipher.final()]).toString(
      "utf8",
    ),
  );
}
export function hiveLoginConfigured() {
  return Boolean(process.env.HIVE_OAUTH_DISCOVERY_URL && process.env.HIVE_OAUTH_CLIENT_ID && process.env.HIVE_OAUTH_ISSUER && process.env.HIVE_OAUTH_API_AUDIENCE === "cindertrace" && process.env.DASHBOARD_PUBLIC_ORIGIN && process.env.CINDERTRACE_API_BROWSER_AUTH === "true");
}
function httpsOrigin(value:string) {const url=new URL(value);if(url.protocol!=="https:"||url.username||url.password||url.search||url.hash||url.pathname!=="/")throw Error("Exact HTTPS origin required");return url.origin;}
function settings() {
 if(!hiveLoginConfigured())throw Error("Oathweave sign-in is not configured");
 const discovery=new URL(process.env.HIVE_OAUTH_DISCOVERY_URL!),issuer=process.env.HIVE_OAUTH_ISSUER!,origin=httpsOrigin(process.env.DASHBOARD_PUBLIC_ORIGIN!);
 const issuerURL=new URL(issuer);if(issuerURL.protocol!=="https:"||issuerURL.username||issuerURL.password||issuerURL.search||issuerURL.hash||discovery.origin!==issuerURL.origin||discovery.username||discovery.password||discovery.hash)throw Error("Verified identity discovery required");
 if(process.env.HIVE_OAUTH_CLIENT_SECRET)throw Error("Register the console as a public PKCE client without a shared client secret");
 const backchannel=process.env.HIVE_OAUTH_BACKCHANNEL_ORIGIN?httpsOrigin(process.env.HIVE_OAUTH_BACKCHANNEL_ORIGIN):undefined;
 return {discovery,issuer,origin,backchannel,clientId:process.env.HIVE_OAUTH_CLIENT_ID!,audience:"cindertrace",callback:`${origin}/api/auth/hive/callback`};
}
/** Only operator-pinned identity requests may use a verified private HTTPS origin. */
export function identityRequestURL(value:string):string {
 const config=settings(),url=new URL(value);
 if(url.origin!==new URL(config.issuer).origin||url.protocol!=="https:"||url.username||url.password||url.hash)throw Error("Unexpected identity endpoint origin");
 if(config.backchannel){const transport=new URL(config.backchannel);transport.pathname=url.pathname;transport.search=url.search;return transport.toString();}return url.toString();
}
async function json(url:string,init?:RequestInit) {
 const res=await fetch(identityRequestURL(url),{...init,redirect:"error",signal:AbortSignal.timeout(8000),cache:"no-store"});if(!res.ok)throw Error("Identity request failed");
 const reader=res.body?.getReader();if(!reader)throw Error("Empty identity response");const chunks:Uint8Array[]=[];let bytes=0;try{for(;;){const part=await reader.read();if(part.done)break;bytes+=part.value.byteLength;if(bytes>65536)throw Error("Identity response too large");chunks.push(part.value);}}finally{await reader.cancel();}return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}
async function discovery() {
 const config=settings(),doc=await json(config.discovery.toString()) as Record<string,unknown>;if(doc.issuer!==config.issuer)throw Error("Identity issuer mismatch");
 for(const key of ["authorization_endpoint","token_endpoint","jwks_uri","userinfo_endpoint"]){if(typeof doc[key]!=="string")throw Error("Incomplete identity discovery");identityRequestURL(doc[key] as string);}
 return {config,doc:doc as Record<string,string>};
}
export async function beginHiveLogin() {
 const {config,doc}=await discovery(),state=randomBytes(32).toString("base64url"),verifier=randomBytes(32).toString("base64url"),nonce=randomBytes(32).toString("base64url");
 await(await store()).set(`cindertrace:hive:oauth:${state}`,seal({verifier,nonce,callback:config.callback,clientId:config.clientId,issuer:config.issuer},state),"EX",300);
 const url=new URL(doc.authorization_endpoint!);url.search=new URLSearchParams({response_type:"code",client_id:config.clientId,redirect_uri:config.callback,scope:"openid profile",state,nonce,code_challenge:createHash("sha256").update(verifier).digest("base64url"),code_challenge_method:"S256"}).toString();return {state,url:url.toString()};
}
export async function finishHiveLogin(state:string,code:string):Promise<{cookie:string}> {
 if(!/^[A-Za-z0-9_-]{43}$/.test(state)||!code||code.length>4096)throw Error("Invalid OAuth callback");
 const saved=await(await store()).getdel(`cindertrace:hive:oauth:${state}`);if(!saved)throw Error("OAuth state expired or already consumed");
 const previous=open(saved,state) as {verifier:string;nonce:string;callback:string;clientId:string;issuer:string},{config,doc}=await discovery();if(previous.callback!==config.callback||previous.clientId!==config.clientId||previous.issuer!==config.issuer||!previous.nonce)throw Error("OAuth transaction configuration changed");
 const response=await json(doc.token_endpoint!,{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams({grant_type:"authorization_code",code,client_id:config.clientId,redirect_uri:config.callback,code_verifier:previous.verifier})});
 if(typeof response.access_token!=="string"||typeof response.id_token!=="string"||response.token_type!=="Bearer")throw Error("Identity tokens required");
 const keys=createRemoteJWKSet(new URL(doc.jwks_uri!),{[customFetch]:(url,init)=>fetch(identityRequestURL(String(url)),{...init,redirect:"error",signal:AbortSignal.timeout(8000)})});
 const {payload}=await jwtVerify(response.id_token,keys,{algorithms:["RS256"],issuer:config.issuer,audience:config.clientId,requiredClaims:["sub","iat","exp","nonce"],maxTokenAge:"15m"});
 if(payload.aud!==config.clientId||payload.nonce!==previous.nonce||typeof payload.sub!=="string"||!payload.sub)throw Error("Invalid identity nonce or subject");
 if(payload.at_hash!==undefined&&payload.at_hash!==createHash("sha256").update(response.access_token).digest().subarray(0,16).toString("base64url"))throw Error("Identity access-token binding failed");
 const resource=await jwtVerify(response.access_token,keys,{algorithms:["RS256"],issuer:config.issuer,audience:config.audience,requiredClaims:["sub","iat","exp"],maxTokenAge:"15m"});
 if(resource.payload.aud!==config.audience||resource.payload.sub!==payload.sub||resource.payload.actorType!=="USER")throw Error("Resource token identity mismatch");
 const api=httpsOrigin(process.env.CINDERTRACE_API_URL??process.env.CONTROL_API_URL??"");
 const exchanged=await fetch(api+"/api/v1/auth/oathweave/session",{method:"POST",headers:{Authorization:"Bearer "+response.access_token,Origin:config.origin},redirect:"error",cache:"no-store",signal:AbortSignal.timeout(10000)});
 if(!exchanged.ok)throw Error("Product identity is inactive, unauthorized or unlinked");
 const {forwardedSessionCookie}=await import("./api-local-auth");const cookie=forwardedSessionCookie(exchanged);if(!cookie)throw Error("Product session missing");return {cookie};
}
export async function hiveCredential(
  session: HiveSessionReference,
  target: string,
) {
  if (session.provider !== "hive") return null;
  if (!session.sessionId || !/^[A-Za-z0-9_-]{43}$/.test(session.sessionId))
    throw new Error("Invalid Hive session");
  const canonical = new URL((process.env["CINDERTRACE_API_URL"] ?? process.env["CONTROL_API_URL"])!);
  if (new URL(target).origin !== canonical.origin)
    throw new Error("Hive delegation is limited to the canonical Control API");
  const encrypted = await (
    await store()
  ).get(`cindertrace:hive:session:${session.sessionId}`);
  if (!encrypted) throw new Error("Hive session expired");
  const value = open(encrypted, session.sessionId) as {
    accessToken: string;
    userId: string;
    expiresAt: number;
  };
  if (value.userId !== session.userId || value.expiresAt <= Date.now() / 1000)
    throw new Error("Hive session identity expired");
  return value.accessToken;
}
export async function revokeHiveSession(session: HiveSessionReference) {
  if (session.provider === "hive" && session.sessionId)
    await (
      await store()
    ).del(`cindertrace:hive:session:${session.sessionId}`);
}
