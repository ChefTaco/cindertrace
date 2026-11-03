import { describe, it, expect } from "vitest";
import { parseUiSecurity } from "./ui-security.js";
const raw = {
  schemaVersion: 1,
  eventId: "12345678-1234-1234-1234-123456789abc",
  occurredAt: "2026-09-17T10:00:00Z",
  application: "magnus_ui",
  event: "auth.login_failed",
  method: "local",
  accountLabel: "a".repeat(24),
  sourceLabel: "b".repeat(24),
  pairLabel: "c".repeat(24),
  sourceAddress: "192.0.2.1",
  password: "must-not-export",
};
const labels = {
  syslog_app: "magnus-ui-security",
  syslog_source_ip: "192.0.2.2",
};
const sources = { magnus_ui: ["192.0.2.2"] };
describe("UI audit ingestion", () => {
  it("supports the standalone console alone without legacy UI sources", () => {
    const event = parseUiSecurity(
      JSON.stringify({ ...raw, application: "cindertrace_ui" }),
      { ...labels, syslog_app: "cindertrace-ui-security" },
      { cindertrace_ui: ["192.0.2.2"] },
    )!;
    expect(event.source).toBe("cindertrace_ui");
    expect(event.summary).toContain("Cindertrace");
    expect(event.eventId).toBe("cindertrace_ui:" + raw.eventId);
  });
  it("preserves stable IDs and excludes unexpected secret-bearing fields", () => {
    const event = parseUiSecurity(JSON.stringify(raw), labels, sources)!;
    expect(event.source).toBe("magnus_ui");
    expect(event.kind).toBe("auth.login_failed");
    expect(event.eventId).toBe("magnus_ui:" + raw.eventId);
    expect(JSON.stringify(event)).not.toContain("must-not-export");
    expect(event.entities[0]?.type).toBe("account");
  });
  it("refuses app identity spoofing and unknown forwarding hosts", () => {
    expect(() =>
      parseUiSecurity(
        JSON.stringify(raw),
        { ...labels, syslog_source_ip: "192.0.2.3" },
        sources,
      ),
    ).toThrow("sender");
    expect(() =>
      parseUiSecurity(
        JSON.stringify({ ...raw, application: "aegis_ui" }),
        labels,
        sources,
      ),
    ).toThrow("Invalid");
  });
  it("retains successful logins as informational observations", () => {
    expect(
      parseUiSecurity(
        JSON.stringify({ ...raw, event: "auth.login_succeeded" }),
        labels,
        sources,
      )?.severity,
    ).toBe("info");
  });
});
