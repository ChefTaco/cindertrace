import { afterEach, beforeEach, expect, it, vi } from "vitest";

type Call = { model: string; method: string; args: any };
const state = vi.hoisted(() => ({
  calls: [] as Array<{ model: string; method: string; args: any }>,
  receipts: [] as Array<Record<string, any>>,
}));
vi.mock("../db/index.js", () => {
  const model = (name: string) =>
    new Proxy(
      {},
      {
        get: (_target, method: string) => async (args: any) => {
          state.calls.push({ model: name, method, args });
          if (method === "count") return name === "securityFusionAssurancePacket" ? 3 : 1;
          if (method === "findMany")
            return name === "securityFusionCase" && args?.where?.archivedAt?.lt
              ? [{ id: "case-archived", archivedAt: new Date("2026-01-01T00:00:00.000Z") }]
              : [];
          if (method === "updateMany" || method === "deleteMany") return { count: 0 };
          return {};
        },
      },
    );
  const models: Record<string, unknown> = {};
  const db: any = new Proxy(
    {},
    {
      get: (_target, prop: string) =>
        prop === "$transaction"
          ? async (fn: (tx: unknown) => unknown) => fn(db)
          : prop === "$queryRaw"
            ? async () => []
            : (models[prop] ??= model(prop)),
    },
  );
  return { getDb: () => db };
});
vi.mock("./security-fusion-receipt-chain.js", () => ({
  appendDeletionReceipts: async (_tx: unknown, receipts: Array<Record<string, any>>) => {
    state.receipts.push(...receipts);
    return { headSha256: null, chainSequence: 0 };
  },
  exportReceiptChainHead: async () => undefined,
}));

const { purgeSecurityFusion } = await import("./security-fusion-service.js");

beforeEach(() => {
  state.calls.length = 0;
  state.receipts.length = 0;
});
afterEach(() => vi.unstubAllEnvs());

it("deletes a case's assurance packets when its archive grace period ends", async () => {
  const result = await purgeSecurityFusion(new Date("2026-11-13T00:00:00.000Z"));
  expect(result.deletedCases).toBe(1);
  const deleted = (model: string): Call | undefined =>
    state.calls.find((call) => call.model === model && call.method === "deleteMany");
  expect(deleted("securityFusionAssurancePacket")?.args).toEqual({
    where: { caseId: "case-archived" },
  });
  // The packets go in the same pass as the case's other content, before the case row.
  const order = state.calls.map((call) => `${call.model}.${call.method}`);
  expect(order.indexOf("securityFusionAssurancePacket.deleteMany")).toBeGreaterThan(-1);
  expect(order.indexOf("securityFusionAssurancePacket.deleteMany")).toBeLessThan(
    order.indexOf("securityFusionCase.delete"),
  );
  const receipt = state.receipts.find((item) => item["resourceType"] === "case");
  expect(JSON.parse(receipt!["detailJson"]).childCounts.assurancePackets).toBe(3);
});
