import { afterEach, describe, expect, it, vi } from "vitest";
import { generateKeyPairSync, sign } from "node:crypto";
import {
  approvalPayloadCanonical,
  requireFreshApproval,
  verifySentiApproval,
} from "./senti-approval.js";

const actor = "a".repeat(64);
function fixture() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  vi.stubEnv(
    "SENTI_APPROVAL_PUBLIC_KEY_B64",
    publicKey.export({ format: "der", type: "spki" }).toString("base64"),
  );
  vi.stubEnv("SENTI_TELEGRAM_ACTOR_SHA256", actor);
  const now = Date.now();
  const payload = {
    version: 2 as const,
    proposal_id: "containment:action-1",
    proposal_revision: 1,
    plan_sha256: "b".repeat(64),
    decision: "approve" as const,
    decision_id: "decision-1",
    decided_at: now,
    expires_at: now + 60_000,
    actor_binding_sha256: actor,
    execution_id: "execution-1",
  };
  const signature = sign(
    null,
    Buffer.from(
      "magnus.senti-approval.v2\n" + approvalPayloadCanonical(payload),
    ),
    privateKey,
  ).toString("base64url");
  return { payload, signature };
}

afterEach(() => vi.unstubAllEnvs());
describe("isolated Senti approval assertion", () => {
  it("accepts a channel-independent Cindertrace decision with its dedicated actor binding", () => {
    const legacy = fixture();
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    vi.stubEnv(
      "SECURITY_APPROVAL_PUBLIC_KEY_B64",
      publicKey.export({ format: "der", type: "spki" }).toString("base64"),
    );
    vi.stubEnv("SECURITY_APPROVAL_ACTOR_SHA256", actor);
    const payload = {
      ...legacy.payload,
      version: 4 as const,
      source_channel: "approval-portal",
    };
    const signature = sign(
      null,
      Buffer.from(
        "cindertrace.external-approval.v4\n" +
          approvalPayloadCanonical(payload),
      ),
      privateKey,
    ).toString("base64url");
    expect(verifySentiApproval({ payload, signature }).payload).toEqual(
      payload,
    );
    vi.stubEnv("SECURITY_APPROVAL_ACTOR_SHA256", "d".repeat(64));
    expect(() => verifySentiApproval({ payload, signature })).toThrow(
      "authentication failed",
    );
    expect(() =>
      requireFreshApproval({
        ...payload,
        expires_at: payload.decided_at + 600001,
      }),
    ).toThrow("invalid lifetime");
  });
  it("accepts an Ed25519 decision bound to the configured Telegram actor", () => {
    const assertion = fixture();
    expect(verifySentiApproval(assertion).payload).toEqual(assertion.payload);
    expect(() =>
      requireFreshApproval(assertion.payload, assertion.payload.decided_at + 1),
    ).not.toThrow();
  });
  it("accepts v3 iPhone decisions only against the iPhone actor binding", () => {
    const legacy = fixture();
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    vi.stubEnv(
      "SENTI_APPROVAL_PUBLIC_KEY_B64",
      publicKey.export({ format: "der", type: "spki" }).toString("base64"),
    );
    vi.stubEnv("SENTI_IPHONE_ACTOR_SHA256", actor);
    const payload = {
      ...legacy.payload,
      version: 3 as const,
      source_channel: "iphone" as const,
    };
    const signature = sign(
      null,
      Buffer.from(
        "magnus.senti-approval.v3\n" + approvalPayloadCanonical(payload),
      ),
      privateKey,
    ).toString("base64url");
    expect(verifySentiApproval({ payload, signature }).payload).toEqual(
      payload,
    );
    vi.stubEnv("SENTI_IPHONE_ACTOR_SHA256", "d".repeat(64));
    expect(() => verifySentiApproval({ payload, signature })).toThrow(
      "authentication failed",
    );
  });
  it("rejects copied signatures, actor changes and unavailable signer configuration", () => {
    const assertion = fixture();
    expect(() =>
      verifySentiApproval({
        ...assertion,
        payload: { ...assertion.payload, plan_sha256: "c".repeat(64) },
      }),
    ).toThrow("authentication failed");
    vi.stubEnv("SENTI_TELEGRAM_ACTOR_SHA256", "d".repeat(64));
    expect(() => verifySentiApproval(assertion)).toThrow(
      "authentication failed",
    );
    vi.stubEnv("SENTI_TELEGRAM_ACTOR_SHA256", actor);
    vi.stubEnv("SENTI_APPROVAL_PUBLIC_KEY_B64", "");
    expect(() => verifySentiApproval(assertion)).toThrow("signer is required");
  });
});
