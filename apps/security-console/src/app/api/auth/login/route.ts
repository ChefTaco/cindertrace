import {useApiLocalAuth,apiLocalRequest,forwardedSessionCookie} from "@/lib/api-local-auth";
import { readBoundedBody, PayloadTooLargeError } from "@/lib/request-body";
import {recordSecurityEvent} from '@/lib/security-events';
/**
 * POST /api/auth/login
 *
 * Authenticates with dashboard credentials from environment variables.
 *
 * Redis-backed source, username, pair, delay, and concurrency protection.
 */
import { NextResponse } from "next/server";
import {
  validateCredentials,
  createSessionToken,
  COOKIE_NAME,
  SESSION_DURATION,
} from "@/lib/auth";
import {
  beginAuthentication,
  resolveTrustedClientAddress,
} from "@/lib/auth-protection";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: Request): Promise<NextResponse> {
  if (req.headers.get("origin") !== process.env["DASHBOARD_PUBLIC_ORIGIN"]) return NextResponse.json({ error: "Invalid origin" }, { status: 403 });
  if(useApiLocalAuth()){
    try {
      const raw=await readBoundedBody(req,4096);let candidate:unknown;try{candidate=JSON.parse(raw);}catch{return NextResponse.json({error:"Invalid request"},{status:400});}
      if(!candidate||typeof candidate!=="object"||Array.isArray(candidate))return NextResponse.json({error:"Invalid request"},{status:400});
      const body=candidate as Record<string,unknown>;
      const response=await apiLocalRequest("login",{body:JSON.stringify({username:body.username??body.email,password:body.password})});
      const payload=await response.text();if(Buffer.byteLength(payload)>16384)throw Error("Invalid authentication response");
      const result=new NextResponse(payload,{status:response.status,headers:{"Content-Type":"application/json","Cache-Control":"no-store"}});
      const cookie=forwardedSessionCookie(response);if(cookie)result.headers.set("Set-Cookie",cookie);
      const retry=response.headers.get("Retry-After");if(retry)result.headers.set("Retry-After",retry);
      return result;
    }catch(error){return NextResponse.json({error:error instanceof PayloadTooLargeError?"Request too large":"Authentication temporarily unavailable"},{status:error instanceof PayloadTooLargeError?413:503});}
  }
  let permit: Awaited<ReturnType<typeof beginAuthentication>> | undefined;
  let auditUsername = '';
  let stage = 'input';
  const respond = async (response: NextResponse) => {
    const event = response.status === 200 ? 'auth.login_succeeded' : response.status === 401 ? 'auth.login_failed' : response.status === 429 ? 'auth.login_throttled' : response.status >= 500 ? 'auth.login_error' : 'auth.login_rejected';
    await recordSecurityEvent(event, req.headers, auditUsername);
    return response;
  };
  try {
    const declaredLength = Number(req.headers.get("content-length") ?? 0);
    if (declaredLength > 4_096)
      return await respond(NextResponse.json({ error: "Request too large" }, { status: 413 }));
    const rawBody = await readBoundedBody(req, 4096);
    if (Buffer.byteLength(rawBody) > 4_096)
      return await respond(NextResponse.json({ error: "Request too large" }, { status: 413 }));
    const body: unknown = JSON.parse(rawBody);
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return await respond(NextResponse.json({ error: "Invalid request" }, { status: 400 }));
    }
    const candidate = body as Record<string, unknown>;
    const password =
      typeof candidate.password === "string" ? candidate.password : "";
    const usernameValue = candidate.username ?? candidate.email;
    const username = typeof usernameValue === "string" ? usernameValue : "";

    auditUsername = username;
    if (!username || !password) {
      return await respond(NextResponse.json(
        { error: "Username and password are required" },
        { status: 400 },
      ));
    }

    stage = 'admission';
    permit = await beginAuthentication(
      resolveTrustedClientAddress(req.headers),
      username,
    );
    if (!permit.allowed) {
      return await respond(NextResponse.json(
        { error: "Too many login attempts. Try again later." },
        {
          status: 429,
          headers: { "Retry-After": String(permit.retryAfterSeconds) },
        },
      ));
    }

    stage = 'credentials';
    if (!(await validateCredentials(username, password))) {
      return await respond(NextResponse.json(
        { error: "Invalid credentials" },
        { status: 401 },
      ));
    }

    stage = 'session';
    await permit.clearSuccessfulPair();

    const token = await createSessionToken(username, { role: "ADMIN" });

    const response = NextResponse.json({ ok: true, username, role: "ADMIN" });
    response.cookies.set(COOKIE_NAME, token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: SESSION_DURATION,
    });
    stage = 'audit';
    return await respond(response);
  } catch (error) {
    if (error instanceof PayloadTooLargeError) return await respond(NextResponse.json({ error: "Request too large" }, { status: 413 }));
    console.error(JSON.stringify({ event: "auth.unavailable", stage, errorType: error instanceof Error ? error.name : "unknown" }));
    await recordSecurityEvent('auth.login_error', req.headers, auditUsername).catch(() => undefined);
    return NextResponse.json({error: 'Authentication temporarily unavailable'}, {status: 503});
  } finally {
    if (permit) {
      try {
        await permit.release();
      } catch {
        /* lease TTL is the final safety net */
      }
    }
  }
}
