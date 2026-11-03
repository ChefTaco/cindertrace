import { afterEach, expect, it, vi } from "vitest";
import { bridgeSignature, equalSignature, magnusRequest } from "./index.js";
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});
it("binds a bridge request to method, path, body, time and nonce", () => {
  const secret = "fixture-bridge-credential-".repeat(3),
    args = ["POST", "/execute", "123", "nonce", "body"] as const;
  const signature = bridgeSignature(secret, ...args);
  for (let i = 0; i < args.length; i++) {
    const changed = [...args] as string[];
    changed[i] += "changed";
    expect(
      equalSignature(
        signature,
        bridgeSignature(
          secret,
          changed[0]!,
          changed[1]!,
          changed[2]!,
          changed[3]!,
          changed[4]!,
        ),
      ),
    ).toBe(false);
  }
  expect(equalSignature(signature, signature)).toBe(true);
  expect(equalSignature("invalid", signature)).toBe(false);
});
it("rejects unsigned successful replies and never follows redirects", async () => {
  vi.stubEnv("MAGNUS_RESPONSE_URL", "https://magnus.example.com/response");
  vi.stubEnv("MAGNUS_RESPONSE_SECRET", "fixture-bridge-credential-".repeat(3));
  const send = vi.fn().mockResolvedValue(new Response("{}"));
  vi.stubGlobal("fetch", send);
  await expect(magnusRequest("/execution-1")).rejects.toThrow("Unverified");
  expect(send.mock.calls[0]![1]).toMatchObject({
    redirect: "error",
    method: "GET",
  });
});
