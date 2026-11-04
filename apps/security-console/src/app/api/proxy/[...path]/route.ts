import { decodeRouteSegment } from "@/lib/route-segment";
import { readBoundedBody, PayloadTooLargeError } from "@/lib/request-body";
import { NextRequest, NextResponse } from "next/server";
import { securityRequest } from "@/lib/security-api";
async function handler(
  req: NextRequest,
  { params }: { params: Promise<{ path: string[] }> },
) {
  try {
    if (!["GET", "POST", "PATCH", "DELETE"].includes(req.method))
      return NextResponse.json(
        { error: "Method not allowed" },
        { status: 405 },
      );
    if (
      req.method !== "GET" &&
      req.headers.get("origin") !== process.env["DASHBOARD_PUBLIC_ORIGIN"]
    )
      return NextResponse.json({ error: "Invalid origin" }, { status: 403 });
    let parts: string[];
    try { parts = (await params).path.map(decodeRouteSegment); }
    catch { return NextResponse.json({ error: "Invalid path" }, { status: 400 }); }
    if (
      parts.some(
        (p) =>
          !p || p === "." || p === ".." || p.includes("/") || p.includes("\\"),
      )
    )
      return NextResponse.json({ error: "Invalid path" }, { status: 400 });
    const raw = req.method === "GET" ? undefined : await readBoundedBody(req, 262144);
    if (raw && Buffer.byteLength(raw) > 262144)
      return NextResponse.json({ error: "Payload too large" }, { status: 413 });
    const response = await securityRequest(
      parts.map(encodeURIComponent).join("/") + req.nextUrl.search,
      { method: req.method, body: raw },
    );
    return new NextResponse(await response.text(), {
      status: response.status,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
      },
    });
  } catch (error) {
    if (error instanceof PayloadTooLargeError) return NextResponse.json({ error: "Payload too large" }, { status: 413 });
    return NextResponse.json(
      { error: "Security service unavailable" },
      { status: 503 },
    );
  }
}
export { handler as GET, handler as POST, handler as PATCH, handler as DELETE };
