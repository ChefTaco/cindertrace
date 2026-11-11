import { Hono } from "hono";
import { expect, it } from "vitest";
import { bodyLimitMiddleware } from "./body-limit.js";
import { app as server } from "../server.js";

function chunkedBody(size: number, chunkSize = 1): ReadableStream<Uint8Array> {
  let remaining = size;
  return new ReadableStream({
    pull(controller) {
      if (remaining === 0) return controller.close();
      const length = Math.min(chunkSize, remaining);
      remaining -= length;
      controller.enqueue(new Uint8Array(length).fill(120));
    },
  });
}

it("coalesces tiny chunks instead of retaining and replaying one object per byte", async () => {
  const app = new Hono();
  app.use("*", bodyLimitMiddleware(65536));
  app.post("/ingest", async (c) => {
    const reader = c.req.raw.body!.getReader();
    let chunks = 0;
    let bytes = 0;
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      chunks++;
      bytes += next.value.length;
      expect(next.value.every((byte) => byte === 120)).toBe(true);
    }
    return c.json({ chunks, bytes });
  });
  const response = await app.request("/ingest", {
    method: "POST",
    body: chunkedBody(65536),
    duplex: "half",
  } as RequestInit);
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual({ chunks: 1, bytes: 65536 });
});

it("rejects a streaming request above the real server limit before routing", async () => {
  const response = await server.request("/api/v1/security-fusion/ingest/source-status", {
    method: "POST",
    body: chunkedBody(262145, 256),
    duplex: "half",
  } as RequestInit);
  expect(response.status).toBe(413);
  expect(await response.json()).toEqual({
    success: false,
    error: { code: "PAYLOAD_TOO_LARGE", message: "Request body exceeds 262144 bytes" },
  });
});
