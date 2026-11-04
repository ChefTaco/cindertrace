import { describe, expect, it, vi } from "vitest";
import { CindertraceClient } from "./cindertrace.js";
describe("scoped Cindertrace agent adapter", () => {
  it("uses independent read and draft credentials and encodes case identities", async () => {
    const request = vi.fn(
      async () => new Response('{"success":true,"data":{}}'),
    );
    const client = new CindertraceClient({
      url: "https://security.example.com",
      readToken: "fixture-read",
      draftToken: "fixture-draft",
      fetchImpl: request as typeof fetch,
    });
    await client.case("case/one");
    expect(request.mock.calls[0]).toEqual([
      "https://security.example.com/api/v1/security-fusion/cases/case%2Fone",
      expect.objectContaining({
        method: "GET",
        redirect: "error",
        headers: expect.objectContaining({
          authorization: "Bearer fixture-read",
        }),
      }),
    ]);
    const draft = {
      summary: "Synthetic investigation",
      hypotheses: [],
      prioritizedChecks: [],
      proposedActions: [],
      evidenceSteps: [],
    };
    await client.draftInvestigation("case-1", draft);
    expect(request.mock.calls[1]).toEqual([
      expect.stringContaining("/case-1/investigations"),
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          authorization: "Bearer fixture-draft",
        }),
      }),
    ]);
    const readOnly = new CindertraceClient({
      url: "https://security.example.com",
      readToken: "fixture-read",
      fetchImpl: request as typeof fetch,
    });
    await expect(readOnly.draftInvestigation("case-1", draft)).rejects.toThrow(
      "separate scoped",
    );
    expect("approve" in client).toBe(false);
  });
  it("rejects insecure origins and limits response bodies", async () => {
    expect(
      () =>
        new CindertraceClient({
          url: "http://security.example.com",
          readToken: "fixture-read",
        }),
    ).toThrow("HTTPS");
    const client = new CindertraceClient({
      url: "https://security.example.com",
      readToken: "fixture-read",
      fetchImpl: vi.fn(
        async () => new Response("x".repeat(2_000_001)),
      ) as typeof fetch,
    });
    await expect(client.events()).rejects.toThrow("limit exceeded");
  });
});
it('uses a third independent credential for lab progression and exposes no approval method', async () => {
  const request = vi.fn(async () => new Response('{"success":true,"data":{}}'));
  const client = new CindertraceClient({url: 'https://security.example.com', readToken: 'fixture-read', draftToken: 'fixture-draft', labControlToken: 'fixture-control', fetchImpl: request as typeof fetch});
  await client.advanceLab('run/one', {stage: 1, evidenceSha256: 'a'.repeat(64)});
  expect(request.mock.calls[0]).toEqual([expect.stringContaining('/lab/runs/run%2Fone/advance'), expect.objectContaining({headers: expect.objectContaining({authorization: 'Bearer fixture-control'})})]);
  expect('approveSimulation' in client).toBe(false);
  const readOnly = new CindertraceClient({url: 'https://security.example.com', readToken: 'fixture-read', fetchImpl: request as typeof fetch});
  await expect(readOnly.advanceLab('run', {stage: 1, evidenceSha256: 'a'.repeat(64)})).rejects.toThrow('lab-control');
});
