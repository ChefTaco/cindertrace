import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { z } from "zod";
export { CindertraceClient } from "./cindertrace.js";
const digest = z.string().regex(/^[a-f0-9]{64}$/);
export const responseRequestSchema = z
  .object({
    version: z.literal(1),
    executionId: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/),
    actionId: z.string().min(1).max(160),
    caseId: z.string().min(1).max(160),
    operation: z.enum(["execute", "release"]),
    nodeId: z.string().min(1).max(160),
    kind: z.enum(["service_restart", "host_isolation"]),
    serviceName: z
      .string()
      .regex(/^[a-zA-Z0-9@_.-]{1,200}$/)
      .nullable(),
    isolationMinutes: z.number().int().min(1).max(30).nullable(),
    previewSha256: digest,
    planSha256: digest,
    approvalId: z.string().min(1).max(160),
    approvedBy: z.string().min(1).max(200),
    expiresAt: z.number().int().positive(),
  })
  .strict();
export type ResponseRequest = z.infer<typeof responseRequestSchema>;
export function bridgeSignature(
  secret: string,
  method: string,
  path: string,
  timestamp: string,
  nonce: string,
  body: string,
): string {
  if (secret.length < 32)
    throw new Error("Dedicated bridge secret is required");
  return createHmac("sha256", secret)
    .update(
      `cindertrace.magnus-response.v1\n${method}\n${path}\n${timestamp}\n${nonce}\n${body}`,
    )
    .digest("hex");
}
export function equalSignature(a: string, b: string): boolean {
  return (
    /^[a-f0-9]{64}$/.test(a) &&
    /^[a-f0-9]{64}$/.test(b) &&
    timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"))
  );
}
export async function magnusRequest(
  path: string,
  body?: ResponseRequest,
): Promise<unknown> {
  const base = process.env["MAGNUS_RESPONSE_URL"];
  const secret = process.env["MAGNUS_RESPONSE_SECRET"] ?? "";
  if (!base || new URL(base).protocol !== "https:")
    throw new Error("Magnus response is not configured");
  const url = new URL(base.replace(/\/$/, "") + path);
  const method = body ? "POST" : "GET",
    raw = body ? JSON.stringify(responseRequestSchema.parse(body)) : "";
  const nonce = randomBytes(16).toString("hex"),
    timestamp = String(Date.now());
  const response = await fetch(url, {
    method,
    body: body ? raw : undefined,
    redirect: "error",
    signal: AbortSignal.timeout(body ? 145000 : 15000),
    headers: {
      "content-type": "application/json",
      "x-cindertrace-time": timestamp,
      "x-cindertrace-nonce": nonce,
      "x-cindertrace-signature": bridgeSignature(
        secret,
        method,
        url.pathname,
        timestamp,
        nonce,
        raw,
      ),
    },
  });
  if (!response.ok) throw new Error(`Magnus bridge HTTP ${response.status}`);
  const reader = response.body?.getReader();
  let size = 0;
  const parts: Uint8Array[] = [];
  if (!reader) throw new Error("Missing bridge response");
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.length;
      if (size > 2_000_000) throw new Error("Oversized bridge response");
      parts.push(chunk.value);
    }
  } finally {
    await reader.cancel();
  }
  const text = Buffer.concat(parts).toString("utf8");
  if (
    !equalSignature(
      response.headers.get("x-cindertrace-signature") ?? "",
      bridgeSignature(secret, "RESPONSE", url.pathname, timestamp, nonce, text),
    )
  )
    throw new Error("Unverified bridge response");
  return JSON.parse(text);
}
