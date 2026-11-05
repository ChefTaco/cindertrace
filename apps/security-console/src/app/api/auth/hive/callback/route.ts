import {recordSecurityEvent} from '@/lib/security-events';
import { NextRequest, NextResponse } from "next/server";
import { finishHiveLogin } from "@/lib/hive-login";
import { configuredLoginReturnURL } from "@/lib/login-return";

export async function GET(req: NextRequest) {
  const query=req.nextUrl.searchParams;
  const state = query.get("state");
  if (["state","code","iss"].some(key=>query.getAll(key).length!==1)||query.get("iss")!==process.env.HIVE_OAUTH_ISSUER||!query.get("code")||!state || state !== req.cookies.get("cindertrace_hive_state")?.value)
    { await recordSecurityEvent('auth.oauth_rejected', req.headers, '', 'hive').catch(() => undefined); return NextResponse.json({ error: "Invalid OAuth state" }, { status: 401 }); }
  try {
    const landing = configuredLoginReturnURL();
    const session = await finishHiveLogin(
      state,
      req.nextUrl.searchParams.get("code") ?? "",
    );

    const response = NextResponse.redirect(landing);
    response.headers.set("Cache-Control","no-store");
    response.cookies.set("cindertrace_hive_state", "", {
      secure: true,
      httpOnly: true,
      path: "/api/auth/hive/callback",
      maxAge: 0,
    });
    response.headers.append("Set-Cookie",session.cookie);
    return response;
  } catch {
    await recordSecurityEvent('auth.login_failed', req.headers, '', 'hive').catch(() => undefined);
    return NextResponse.json({ error: "Oathweave sign-in failed" }, { status: 401 });
  }
}
