import { afterEach, expect, it, vi } from "vitest";
const future = new Date(Date.now() + 60_000);
vi.mock("../db/index.js", () => {
  const tx = {
    $executeRaw: async () => 1,
    securityFusionAction: { findUnique: async () => ({ id: "a1", status: "pending_approval", requestedBy: "previewer" }) },
    securityFusionActionApproval: { findUnique: async () => ({ actionId: "a1", status: "pending", expiresAt: future, requestedBy: "requester" }) },
  };
  return { getDb: () => ({ $transaction: (fn: (db: typeof tx) => unknown) => fn(tx) }) };
});
vi.mock("./senti-containment-approval.js", () => ({
  validateStoredContainmentPlan: () => {
    throw Object.assign(new Error("reached the plan check"), { code: "REACHED" });
  },
}));
const { decideAsAdmin } = await import("./approval-decisions.js");
const exact = { confirmed: true, planSha256: "a".repeat(64), previewSha256: "b".repeat(64) };
afterEach(() => vi.unstubAllEnvs());
it("refuses approval by whoever previewed or requested the action when two-person approval is on", async () => {
  vi.stubEnv("MAGNUS_RESPONSE_URL", "https://magnus.example.com/response");
  vi.stubEnv("MAGNUS_RESPONSE_SECRET", "m".repeat(40));
  vi.stubEnv("SECURITY_DISPATCH_ENABLED", "true");
  vi.stubEnv("SECURITY_APPROVAL_DISTINCT_APPROVER", "true");
  for (const actor of ["previewer", "requester"])
    await expect(decideAsAdmin("a1", actor, "approve", exact)).rejects.toMatchObject({ code: "DISTINCT_APPROVER_REQUIRED", status: 403 });
  // Another administrator, or a rejection by the requester, proceeds to the plan check.
  await expect(decideAsAdmin("a1", "second-admin", "approve", exact)).rejects.toMatchObject({ code: "REACHED" });
  await expect(decideAsAdmin("a1", "requester", "reject", exact)).rejects.toMatchObject({ code: "REACHED" });
  vi.stubEnv("SECURITY_APPROVAL_DISTINCT_APPROVER", "false");
  await expect(decideAsAdmin("a1", "requester", "approve", exact)).rejects.toMatchObject({ code: "REACHED" });
});
