import type { SecurityFusionEvent } from "@cindertrace/contracts";
import { describe, expect, it, vi } from "vitest";
import {
  BoundedSecurityEventQueue,
  boundedFetch,
  parseBoundedJson,
  readResponseBodyBounded,
  readSecurityCollectorRuntimeConfig,
  singleFlight,
} from "./runtime-security.js";

const ingestSecret = "security-fusion-ingest-secret-with-32-plus-characters";

function event(eventId: string): SecurityFusionEvent {
  return {
    schemaVersion: "1.0",
    eventId,
    source: "magnus",
    sourceEventId: eventId,
    kind: "test.event",
    observedAt: "2026-08-07T20:00:00.000Z",
    severity: "info",
    confidence: 1,
    summary: `Event ${eventId}`,
    entities: [],
    attributes: {},
    evidence: [],
  };
}

describe("security collector runtime guards", () => {
  it("starts without external integrations and rejects partial or retired source configuration", () => {
    const base = { SECURITY_FUSION_INGEST_SECRET: ingestSecret };
    expect(() => readSecurityCollectorRuntimeConfig(base)).not.toThrow();
    expect(() =>
      readSecurityCollectorRuntimeConfig({
        ...base,
        TAILSCALE_SECURITY_TOKEN: "fixture-token",
      }),
    ).toThrow("explicit tailnet");
    expect(() =>
      readSecurityCollectorRuntimeConfig({
        ...base,
        HIVE_SECURITY_EXPORT_TOKEN: "fixture-retired-token",
      }),
    ).toThrow("retired");
    expect(() =>
      readSecurityCollectorRuntimeConfig({
        ...base,
        HIVE_SECURITY_EXPORT_URL:
          "https://router.example.com/api/security/events",
      }),
    ).toThrow("scoped OAuth");
    expect(() =>
      readSecurityCollectorRuntimeConfig({
        ...base,
        CHATTERMOST_SECURITY_EXPORT_URL: "https://chat.example.com/export",
      }),
    ).toThrow("together");
    expect(() =>
      readSecurityCollectorRuntimeConfig({
        ...base,
        LOKI_URL: "http://logs.example.com",
      }),
    ).toThrow("HTTPS");
  });
  it("fails closed without a dedicated strong ingest secret", () => {
    expect(() => readSecurityCollectorRuntimeConfig({})).toThrow(/at least 32/);
    expect(() =>
      readSecurityCollectorRuntimeConfig({
        SECURITY_FUSION_INGEST_SECRET: "short",
      }),
    ).toThrow(/at least 32/);
    expect(() =>
      readSecurityCollectorRuntimeConfig({
        SECURITY_FUSION_INGEST_SECRET: ingestSecret,
        API_SECRET: ingestSecret,
      }),
    ).toThrow(/distinct from API_SECRET/);
  });

  it("validates bounded runtime settings before startup", () => {
    expect(
      readSecurityCollectorRuntimeConfig({
        SECURITY_FUSION_INGEST_SECRET: ingestSecret,
        SECURITY_FUSION_HTTP_TIMEOUT_MS: "2000",
        SECURITY_FUSION_MAX_RESPONSE_BYTES: "2048",
        SECURITY_FUSION_QUEUE_MAX_EVENTS: "100",
      }),
    ).toMatchObject({
      httpTimeoutMs: 2000,
      maxResponseBytes: 2048,
      maxQueueEvents: 100,
    });
    expect(() =>
      readSecurityCollectorRuntimeConfig({
        SECURITY_FUSION_INGEST_SECRET: ingestSecret,
        SECURITY_FUSION_QUEUE_MAX_EVENTS: "0",
      }),
    ).toThrow(/QUEUE_MAX_EVENTS/);
  });
});

describe("bounded event queue", () => {
  it("deduplicates queued events and never exceeds the ingress limit", () => {
    const queue = new BoundedSecurityEventQueue(2, 4);
    expect(queue.enqueue(event("a"))).toBe("accepted");
    expect(queue.enqueue(event("a"))).toBe("duplicate");
    expect(queue.snapshot()[0]?.attributes["observationCount"]).toBe(2);
    expect(queue.enqueue(event("b"))).toBe("accepted");
    expect(queue.enqueue(event("c"))).toBe("full");
    expect(queue.size).toBe(2);
  });

  it("bounds failed-batch requeue and prioritizes the failed batch", () => {
    const queue = new BoundedSecurityEventQueue(2, 8);
    queue.enqueue(event("a"));
    queue.enqueue(event("b"));
    const inFlight = queue.take(2);
    queue.enqueue(event("c"));
    queue.enqueue(event("d"));
    const dropped = queue.requeueFront(inFlight);
    expect(dropped.map((entry) => entry.eventId).sort()).toEqual(["c", "d"]);
    expect(queue.snapshot().map((entry) => entry.eventId)).toEqual(["a", "b"]);
    expect(queue.size).toBe(2);
  });
});

describe("bounded network helpers", () => {
  it("rejects declared and streamed bodies above the byte ceiling", async () => {
    await expect(
      readResponseBodyBounded(
        new Response("oversize", {
          headers: { "content-length": "8" },
        }),
        4,
      ),
    ).rejects.toThrow(/exceeded 4 byte limit/);

    const response = new Response(
      new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new TextEncoder().encode("abc"));
          controller.enqueue(new TextEncoder().encode("def"));
          controller.close();
        },
      }),
    );
    await expect(readResponseBodyBounded(response, 5)).rejects.toThrow(
      /exceeded 5 byte limit/,
    );
  });

  it("aborts a request at its deadline and parses only bounded JSON", async () => {
    const neverCompletes = vi.fn<typeof fetch>(
      (_input, init) =>
        new Promise<Response>((_resolve, reject) => {
          const signal = init?.signal;
          if (!signal)
            throw new Error("test request did not receive an abort signal");
          const rejectWithReason = () => reject(signal.reason);
          if (signal.aborted) rejectWithReason();
          else
            signal.addEventListener("abort", rejectWithReason, { once: true });
        }),
    );
    await expect(
      boundedFetch(
        "https://collector.test",
        {},
        {
          timeoutMs: 10,
          maxResponseBytes: 1024,
          fetchImpl: neverCompletes,
        },
      ),
    ).rejects.toMatchObject({ name: "TimeoutError" });

    const result = await boundedFetch(
      "https://collector.test",
      {},
      {
        timeoutMs: 1000,
        maxResponseBytes: 1024,
        fetchImpl: vi.fn<typeof fetch>(async () => new Response('{"ok":true}')),
      },
    );
    expect(parseBoundedJson<{ ok: boolean }>(result.body, "fixture")).toEqual({
      ok: true,
    });
  });
});

describe("single flight", () => {
  it("shares one in-flight poll or flush operation", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const operation = vi.fn(async () => {
      await gate;
      return "done";
    });
    const run = singleFlight(operation);
    const first = run();
    const second = run();
    expect(first).toBe(second);
    expect(operation).toHaveBeenCalledTimes(1);
    release();
    await expect(first).resolves.toBe("done");
    await expect(run()).resolves.toBe("done");
    expect(operation).toHaveBeenCalledTimes(2);
  });
});
