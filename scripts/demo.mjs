import { createHmac, randomBytes, createHash } from "node:crypto";
import { SignJWT } from "jose";
if (process.env.CINDERTRACE_DEMO_CONFIRM !== "isolated-synthetic-installation")
  throw new Error(
    "Demo ingestion requires an explicitly isolated synthetic installation",
  );
const collectorId = process.env.SECURITY_FUSION_COLLECTOR_ID;
const secret = process.env.SECURITY_FUSION_INGEST_SECRET;
if (!collectorId || !secret)
  throw new Error("Load an isolated installation environment first");
const event = {
  schemaVersion: "1.0",
  eventId: createHash("sha256").update("cindertrace-demo-auth-1").digest("hex"),
  source: "wazuh",
  sourceEventId: "cindertrace-demo-auth-1",
  kind: "endpoint.authentication.failure",
  observedAt: new Date().toISOString(),
  severity: "high",
  confidence: 0.94,
  summary: "Repeated authentication failures on the example application host",
  entities: [
    {
      type: "host",
      value: "app-1.example.com",
      label: "Example application host",
    },
    { type: "user", value: "operator@example.com" },
  ],
  attributes: { synthetic: true, failedAttempts: 12 },
  evidence: [
    {
      sourceLocator: "synthetic:authentication-failures",
      mediaType: "application/json",
      snapshot: { synthetic: true, failedAttempts: 12 },
    },
  ],
};
const raw = JSON.stringify({
  schemaVersion: "1.0",
  collectorId,
  sentAt: new Date().toISOString(),
  events: [event],
});
const timestamp = new Date().toISOString(),
  nonce = randomBytes(18).toString("base64url");
const result = await fetch(
  `${process.env.CINDERTRACE_API_URL}/api/v1/security-fusion/ingest/events`,
  {
    method: "POST",
    redirect: "error",
    headers: {
      "content-type": "application/json",
      "x-security-collector-id": collectorId,
      "x-security-timestamp": timestamp,
      "x-security-nonce": nonce,
      "x-security-signature": createHmac("sha256", secret)
        .update(`${collectorId}.${timestamp}.${nonce}.${raw}`)
        .digest("hex"),
    },
    body: raw,
  },
);
if (!result.ok) throw new Error(`Demo ingestion HTTP ${result.status}`);
if (process.argv.includes("--preserve")) {
  const body = await result.json();
  const token = await new SignJWT({ userId: "synthetic-demo", role: "ADMIN" })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer("cindertrace-console")
    .setAudience("cindertrace-api")
    .setIssuedAt()
    .setExpirationTime("60s")
    .sign(new TextEncoder().encode(process.env.SECURITY_CONSOLE_TOKEN_SECRET));
  for (const id of body.data.caseIds) {
    const headers = { authorization: `Bearer ${token}` };
    const detail = await fetch(
      `${process.env.CINDERTRACE_API_URL}/api/v1/security-fusion/cases/${id}`,
      { headers, redirect: "error" },
    );
    if (!detail.ok) throw new Error("Synthetic case read failed");
    const data = await detail.json();
    const preserved = await fetch(
      `${process.env.CINDERTRACE_API_URL}/api/v1/security-fusion/cases/${id}/evidence/${data.data.events[0].id}/preserve`,
      { method: "POST", headers, redirect: "error" },
    );
    if (!preserved.ok)
      throw new Error("Synthetic evidence preservation failed");
  }
}
console.log("Synthetic demo observation ingested. Open Cases in Cindertrace.");
