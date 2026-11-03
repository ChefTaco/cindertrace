import { revokeLocalSession } from "@/lib/local-sessions";
import { recordSecurityEvent } from "@/lib/security-events";
/**
 * POST /api/auth/logout
 *
 * Clears the local dashboard session cookie.
 */
import { NextResponse, type NextRequest } from "next/server";
import { COOKIE_NAME, verifySessionToken } from "@/lib/auth";
import { cookies } from "next/headers";
import { revokeHiveSession } from "@/lib/hive-login";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: NextRequest): Promise<NextResponse> {
  if (request.headers.get("origin") !== process.env["DASHBOARD_PUBLIC_ORIGIN"]) return NextResponse.json({ error: "Invalid origin" }, { status: 403 });
  const token = (await cookies()).get(COOKIE_NAME)?.value;
  let session;
  try {
    session = token ? await verifySessionToken(token, true) : null;
  } catch {
    return NextResponse.json(
      { error: "Session revocation unavailable; retry sign out" },
      { status: 503 },
    );
  }
  if (session)
    await recordSecurityEvent(
      "auth.logout",
      request.headers,
      session.username,
      session.provider === "hive" ? "hive" : "local",
    ).catch(() => undefined);
  if (session) {
    try {
      if (session.provider === "hive") await revokeHiveSession(session);
      else
        await revokeLocalSession(
          session,
          request.nextUrl.searchParams.get("all") === "true",
        );
    } catch {
      return NextResponse.json(
        { error: "Session revocation unavailable; retry sign out" },
        { status: 503 },
      );
    }
  }
  const response = request.headers.get("accept")?.includes("text/html")
    ? NextResponse.redirect(
        new URL(
          "/login",
          process.env["DASHBOARD_PUBLIC_ORIGIN"] ?? request.url,
        ),
        303,
      )
    : NextResponse.json({ ok: true });

  response.cookies.set(COOKIE_NAME, "", {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: 0,
  });

  return response;
}
