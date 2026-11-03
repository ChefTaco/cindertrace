import assert from "node:assert/strict";
import { randomUUID, createHmac, createHash, randomBytes } from "node:crypto";
import { mkdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
if (
  !/^cindertrace_test_[a-z0-9_]+$/.test(
    new URL(process.env.CINDERTRACE_TEST_DATABASE_URL ?? "").pathname.slice(1),
  )
)
  throw new Error("A disposable cindertrace_test_* database is required");
process.env.DATABASE_URL = process.env.CINDERTRACE_TEST_DATABASE_URL;
const root = resolve(import.meta.dirname, ".."),
  api = resolve(root, "services/security-fusion");
const state = "/state/core-integration-" + randomUUID();
mkdirSync(state, { recursive: true, mode: 0o700 });
process.env.AUDIT_LOG_DIR = state + "/audit";
process.env.SECURITY_FUSION_EVIDENCE_DIR = state + "/evidence";
process.env.SECURITY_FUSION_RECEIPT_CHAIN_EXPORT = state + "/receipts.jsonl";
process.env.SECURITY_WRITES_ENABLED = "true";
process.env.SECURITY_INGEST_ENABLED = "true";
process.env.SECURITY_DISPATCH_ENABLED = "false";
execFileSync(process.execPath, ["scripts/apply-migrations.mjs"], {
  cwd: api,
  stdio: "pipe",
});
const { app } = await import("../services/security-fusion/dist/server.js");
const { getDb, disconnectDb } =
  await import("../services/security-fusion/dist/db/index.js");
const { SignJWT } = await import("jose");
const db = getDb();
try {
  await db.securityFusionReceiptChainHead.upsert({
    where: { id: "security-fusion" },
    create: { id: "security-fusion", chainSequence: 0 },
    update: {},
  });
  async function token(role) {
    return new SignJWT({ userId: "fixture-admin", role })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuer("cindertrace-console")
      .setAudience("cindertrace-api")
      .setIssuedAt()
      .setExpirationTime("60s")
      .sign(
        new TextEncoder().encode(process.env.SECURITY_CONSOLE_TOKEN_SECRET),
      );
  }
  const admin = await token("ADMIN"),
    operator = await token("OPERATOR"),
    viewer = await token("VIEWER");
  const req = (path, method = "GET", body, bearer = admin) =>
    app.request("/api/v1/security-fusion" + path, {
      method,
      headers: {
        Authorization: "Bearer " + bearer,
        "content-type": "application/json",
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  assert.equal((await req("/cases", "GET", undefined, viewer)).status, 403);
  assert.equal(
    (await req("/evidence", "GET", undefined, operator)).status,
    403,
  );
  const collectorId = process.env.SECURITY_FUSION_COLLECTOR_ID,
    secret = process.env.SECURITY_FUSION_INGEST_SECRET;
  const event = {
    schemaVersion: "1.0",
    eventId: "fixture-auth-event",
    source: "wazuh",
    sourceEventId: "fixture-auth-event",
    kind: "endpoint.login.failure",
    observedAt: new Date().toISOString(),
    severity: "high",
    confidence: 0.95,
    summary: "Synthetic authentication finding",
    entities: [{ type: "host", value: "app-1.example.com" }],
    attributes: { synthetic: true },
    evidence: [],
  };
  const raw = JSON.stringify({
    schemaVersion: "1.0",
    collectorId,
    sentAt: new Date().toISOString(),
    events: [event],
  });
  const timestamp = new Date().toISOString(),
    nonce = randomBytes(18).toString("base64url");
  const headers = {
    "content-type": "application/json",
    "x-security-collector-id": collectorId,
    "x-security-timestamp": timestamp,
    "x-security-nonce": nonce,
    "x-security-signature": createHmac("sha256", secret)
      .update(`${collectorId}.${timestamp}.${nonce}.${raw}`)
      .digest("hex"),
  };
  const ingest = () =>
    app.request("/api/v1/security-fusion/ingest/events", {
      method: "POST",
      headers,
      body: raw,
    });
  assert.equal((await ingest()).status, 202);
  assert.equal((await ingest()).status, 409);
  const checkpointNonce = randomBytes(18).toString("base64url");
  const checkpointReply = await app.request(
    "/api/v1/security-fusion/ingest/checkpoints",
    {
      headers: {
        ...headers,
        "x-security-nonce": checkpointNonce,
        "x-security-signature": createHmac("sha256", secret)
          .update(`${collectorId}.${timestamp}.${checkpointNonce}.`)
          .digest("hex"),
      },
    },
  );
  assert.equal(checkpointReply.status, 200);
  const checkpointPolicy = await checkpointReply.json();
  assert(checkpointPolicy.allowedSources.includes("cindertrace_ui"));
  assert(checkpointPolicy.allowedSources.includes("wazuh"));
  const uiEvents = ["aegis_ui", "security_console", "cindertrace_ui"].map(
    (source, index) => ({
      ...event,
      source,
      eventId: "alias-" + randomUUID(),
      sourceEventId: "alias-source-" + randomUUID(),
      kind: "auth.login_failed",
      severity: "low",
      summary: "Synthetic console authentication failure",
      observedAt: new Date(Date.now() + index).toISOString(),
      entities: [{ type: "account", value: source + ":fixture-account-pair" }],
    }),
  );
  const uiRaw = JSON.stringify({
    schemaVersion: "1.0",
    collectorId,
    sentAt: new Date().toISOString(),
    events: uiEvents,
  });
  const uiNonce = randomBytes(18).toString("base64url");
  const uiResponse = await app.request(
    "/api/v1/security-fusion/ingest/events",
    {
      method: "POST",
      headers: {
        ...headers,
        "x-security-nonce": uiNonce,
        "x-security-signature": createHmac("sha256", secret)
          .update(`${collectorId}.${timestamp}.${uiNonce}.${uiRaw}`)
          .digest("hex"),
      },
      body: uiRaw,
    },
  );
  assert.equal(uiResponse.status, 202);
  const uiRows = await db.securityFusionEvent.findMany({
    where: { eventId: { in: uiEvents.map((x) => x.eventId) } },
    orderBy: { observedAt: "asc" },
  });
  assert.deepEqual(
    uiRows.map((x) => x.source),
    uiEvents.map((x) => x.source),
  );
  const uiLinks = await db.securityFusionEventEntity.findMany({
    where: { eventId: { in: uiRows.map((x) => x.id) } },
  });
  assert.equal(new Set(uiLinks.map((x) => x.entityId)).size, 1);
  const uiCaseLinks = await db.securityFusionCaseEvent.findMany({
    where: { eventId: { in: uiRows.map((x) => x.id) } },
  });
  assert.equal(uiCaseLinks.length, 3);
  assert.equal(new Set(uiCaseLinks.map((x) => x.caseId)).size, 1);
  const cases = (await (await req("/cases")).json()).data;
  assert(cases.length > 0);
  const detail = (await (await req("/cases/" + cases[0].id)).json()).data;
  assert.equal(detail.responseAvailable, false);
  assert.equal(
    (
      await req(
        `/cases/${cases[0].id}/evidence/${detail.events[0].id}/preserve`,
        "POST",
      )
    ).status,
    201,
  );
  assert.equal(
    (
      await req(`/cases/${cases[0].id}/investigations`, "POST", {
        summary: "Synthetic investigation",
        hypotheses: ["Review example authentication policy"],
        prioritizedChecks: [],
        proposedActions: [],
        evidenceSteps: [],
      })
    ).status,
    201,
  );
  assert.equal(
    (await req("/cases/" + cases[0].id, "GET", undefined, operator)).status,
    200,
  );
  const caseId = cases[0].id;
  const fixture = await db.securityFusionAction.create({
    data: {
      caseId,
      nodeId: "fixture-node",
      kind: "service_restart",
      serviceName: "fixture.service",
      rationale: "Synthetic recovery request",
      rollbackPlan: "Verify application health",
      previewJson: '{"synthetic":true}',
      previewSha256: "a".repeat(64),
      requestedBy: "fixture-admin",
    },
  });
  assert.equal(
    (await req(`/actions/${fixture.id}/request`, "POST")).status,
    503,
  );
  process.env.MAGNUS_RESPONSE_URL = "https://magnus.example.com/response";
  process.env.MAGNUS_RESPONSE_SECRET = "fixture-bridge-credential-".repeat(3);
  const proposal = await req(`/actions/${fixture.id}/request`, "POST");
  assert.equal(proposal.status, 200);
  const plan = (await proposal.json()).data.plan;
  const decision = {
    confirmed: true,
    planSha256: plan.plan_sha256,
    previewSha256: "a".repeat(64),
  };
  assert.equal(
    (
      await req(`/actions/${fixture.id}/approve`, "POST", {
        ...decision,
        planSha256: "b".repeat(64),
      })
    ).status,
    409,
  );
  assert.equal(
    (await req(`/actions/${fixture.id}/approve`, "POST", decision, operator))
      .status,
    403,
  );
  const decisions = await Promise.all([
    req(`/actions/${fixture.id}/approve`, "POST", decision),
    req(`/actions/${fixture.id}/approve`, "POST", decision),
  ]);
  assert.deepEqual(decisions.map((x) => x.status).sort(), [200, 409]);
  assert.equal(
    await db.securityFusionCommandOutbox.count({
      where: { actionId: fixture.id },
    }),
    1,
  );
  assert.equal(
    await db.securityFusionApprovalDecision.count({
      where: { actionId: fixture.id },
    }),
    1,
  );
  process.env.SECURITY_WRITES_ENABLED = "false";
  process.env.SECURITY_DISPATCH_ENABLED = "true";
  const { dispatchSecurityFusionOutbox } =
    await import("../services/security-fusion/dist/services/security-fusion-outbox.js");
  assert.equal(await dispatchSecurityFusionOutbox(), 0);
  assert.equal(
    (
      await db.securityFusionCommandOutbox.findFirstOrThrow({
        where: { actionId: fixture.id },
      })
    ).status,
    "pending",
  );
  // The product owns restart verification after the Magnus extraction. Exercise
  // persistent transitions against PostgreSQL and request-bound signed health.
  process.env.SECURITY_WRITES_ENABLED = "true";
  process.env.SECURITY_DISPATCH_ENABLED = "false";
  const { bridgeSignature } =
    await import("../packages/integrations/dist/index.js");
  const { reconcileRestartVerification } =
    await import("../services/security-fusion/dist/services/security-fusion-outbox.js");
  await db.securityTarget.create({
    data: {
      id: "fixture-node",
      name: "Synthetic application",
      hostname: "app-1.example.com",
      baseUrl: "https://node.example.com:4100",
      tags: "[]",
      metadata: "{}",
      syncedAt: new Date(),
    },
  });
  let healthStatus = "active";
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    const path = new URL(input).pathname;
    assert.equal(init.method, "GET");
    assert.equal(path, "/response/targets/fixture-node/health");
    const body = JSON.stringify({
        data: {
          responseCapable: true,
          services: [{ name: "fixture", status: healthStatus }],
        },
      }),
      headers = new Headers(init.headers);
    return new Response(body, {
      headers: {
        "x-cindertrace-signature": bridgeSignature(
          process.env.MAGNUS_RESPONSE_SECRET,
          "RESPONSE",
          path,
          headers.get("x-cindertrace-time"),
          headers.get("x-cindertrace-nonce"),
          body,
        ),
      },
    });
  };
  try {
    const make = async (deadline) => {
      const action = await db.securityFusionAction.create({
        data: {
          caseId,
          nodeId: "fixture-node",
          kind: "service_restart",
          serviceName: "fixture.service",
          rationale: "Synthetic restart verification",
          rollbackPlan: "Inspect synthetic health",
          previewJson: "{}",
          previewSha256: "d".repeat(64),
          status: "verifying",
          requestedBy: "fixture-admin",
          verificationDeadline: deadline,
        },
      });
      await db.securityExecution.create({
        data: {
          id: randomUUID(),
          actionId: action.id,
          operation: "execute",
          nodeId: "fixture-node",
          status: "completed",
          completedAt: new Date(Date.now() - 300000),
        },
      });
      return action;
    };
    const recovered = await make(new Date(Date.now() - 60000));
    await reconcileRestartVerification();
    assert.equal(
      (
        await db.securityFusionAction.findUniqueOrThrow({
          where: { id: recovered.id },
        })
      ).status,
      "succeeded",
    );
    healthStatus = "failed";
    const unhealthy = await make(new Date(Date.now() + 180000));
    await reconcileRestartVerification();
    assert.equal(
      (
        await db.securityFusionAction.findUniqueOrThrow({
          where: { id: unhealthy.id },
        })
      ).status,
      "verifying",
    );
    await db.securityFusionAction.update({
      where: { id: unhealthy.id },
      data: { verificationDeadline: new Date(Date.now() - 1) },
    });
    await reconcileRestartVerification();
    assert.equal(
      (
        await db.securityFusionAction.findUniqueOrThrow({
          where: { id: unhealthy.id },
        })
      ).status,
      "failed",
    );
    assert.equal(
      await db.securityFusionCaseActivity.count({
        where: { caseId, kind: "containment.succeeded" },
      }),
      1,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
  console.log(
    JSON.stringify({
      standalone: true,
      signedIngestion: true,
      legacySourceCorrelationPreserved: true,
      replayRejected: true,
      evidencePreserved: true,
      investigationSaved: true,
      roleBoundaries: true,
      concurrentApprovalConsumedOnce: true,
      wrongPlanRejected: true,
      dispatchDisabled: true,
      globalWritePausePreventsDispatch: true,
      restartVerificationRecovery: true,
    }),
  );
} finally {
  await disconnectDb();
  const { closeRateLimitRedis } =
    await import("../services/security-fusion/dist/middleware/rate-limit.js");
  await closeRateLimitRedis();
}
