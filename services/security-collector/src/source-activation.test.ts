import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
let state: string | undefined;
afterEach(() => {
  vi.clearAllTimers();
  vi.useRealTimers();
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  if (state) rmSync(state, { recursive: true });
});
it.each([
  ["cindertrace_ui"],
  ["cindertrace_ui", "unifi_ids", "unifi_dns", "netflow"],
])(
  "polls only configured UI audit and reports only admitted sources (%j)",
  async (...allowed) => {
    vi.resetModules();
    vi.useFakeTimers();
    state = mkdtempSync(join(tmpdir(), "cindertrace-source-activation-"));
    for (const name of Object.keys(process.env)) vi.stubEnv(name, undefined);
    for (const [name, value] of Object.entries({
      CINDERTRACE_API_URL: "https://api.example.com",
      SECURITY_FUSION_INGEST_SECRET: "fixture-ingest-credential-".repeat(2),
      SECURITY_FUSION_STATE_DIR: state,
      LOKI_URL: "https://logs.example.com",
      LOKI_READ_TOKEN: "fixture-loki-credential-".repeat(2),
      UI_SECURITY_SOURCES_JSON: JSON.stringify({
        cindertrace_ui: ["192.0.2.2"],
      }),
    }))
      vi.stubEnv(name, value);
    const requests: string[] = [];
    let report:
      { sources: Array<{ source: string; status: string }> } | undefined;
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL, init?: RequestInit) => {
        const url = new URL(input);
        requests.push(url.pathname);
        if (url.pathname.endsWith("/checkpoints"))
          return Response.json({
            success: true,
            allowedSources: allowed,
            data: {},
          });
        if (url.pathname.endsWith("/query_range")) {
          expect(url.searchParams.get("query")).toBe(
            '{job="syslog",syslog_app=~"cindertrace-ui-security"}',
          );
          return Response.json({ status: "success", data: { result: [] } });
        }
        if (url.pathname.endsWith("/source-status")) {
          report = JSON.parse(String(init?.body));
          return Response.json({ success: true }, { status: 202 });
        }
        throw new Error("Unexpected source request");
      }),
    );
    await import("./index.js");
    await vi.waitFor(() => expect(report).toBeDefined());
    expect(report!.sources).toEqual(
      expect.arrayContaining([{ source: "cindertrace_ui", status: "healthy" }]),
    );
    expect(report!.sources.map((x) => x.source).sort()).toEqual(
      [...allowed].sort(),
    );
    expect(
      report!.sources
        .filter((x) => x.source !== "cindertrace_ui")
        .every((x) => x.status === "unconfigured"),
    ).toBe(true);
    expect(requests).toEqual([
      "/api/v1/security-fusion/ingest/checkpoints",
      "/loki/api/v1/query_range",
      "/api/v1/security-fusion/ingest/source-status",
    ]);
  },
);
