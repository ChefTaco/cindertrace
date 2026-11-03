import { isIP } from "node:net";
import type { SecurityFusionEvent } from "@cindertrace/contracts";
export const uiApplications = {
  "magnus-ui-security": "magnus_ui",
  "aegis-ui-security": "aegis_ui",
  "security-console-security": "security_console",
  "cindertrace-ui-security": "cindertrace_ui",
} as const;
export type UiSource = (typeof uiApplications)[keyof typeof uiApplications];
export type UiSources = Partial<Record<UiSource, string[]>>;
const outcomes = new Set([
  "auth.login_failed",
  "auth.login_succeeded",
  "auth.login_throttled",
  "auth.login_rejected",
  "auth.login_error",
  "auth.logout",
  "auth.oauth_rejected",
]);
export function parseUiSecurity(
  line: string,
  labels: Record<string, string>,
  sources: UiSources,
): SecurityFusionEvent | null {
  const app =
    uiApplications[labels["syslog_app"] as keyof typeof uiApplications];
  if (!app) return null;
  const peer = labels["syslog_source_ip"]?.replace(/^::ffff:/, "");
  if (!peer || !sources[app]?.includes(peer))
    throw Error("UI audit sender does not match configured host");
  if (line.length > 4096) throw Error("UI audit line too large");
  const start = line.indexOf("{");
  const row: unknown = JSON.parse(start < 0 ? "null" : line.slice(start));
  if (!row || typeof row !== "object") throw Error("Invalid UI audit JSON");
  const x = row as Record<string, unknown>;
  if (
    x["schemaVersion"] !== 1 ||
    x["application"] !== app ||
    typeof x["event"] !== "string" ||
    !outcomes.has(x["event"]) ||
    typeof x["eventId"] !== "string" ||
    !/^[a-f0-9-]{36}$/.test(x["eventId"]) ||
    typeof x["occurredAt"] !== "string" ||
    !Number.isFinite(Date.parse(x["occurredAt"])) ||
    !["local", "hive"].includes(String(x["method"])) ||
    !["accountLabel", "sourceLabel", "pairLabel"].every(
      (k) => typeof x[k] === "string" && /^[a-f0-9]{24}$/.test(x[k] as string),
    ) ||
    typeof x["sourceAddress"] !== "string" ||
    (x["sourceAddress"] !== "unverified" && !isIP(x["sourceAddress"]))
  )
    throw Error("Invalid UI audit record");
  const safe = {
    application: app,
    event: x["event"],
    method: x["method"],
    accountLabel: x["accountLabel"],
    sourceLabel: x["sourceLabel"],
    pairLabel: x["pairLabel"],
    sourceAddress: x["sourceAddress"],
  };
  return {
    schemaVersion: "1.0",
    eventId: `${app}:${x["eventId"]}`,
    source: app,
    sourceEventId: x["eventId"],
    kind: x["event"],
    observedAt: new Date(x["occurredAt"]).toISOString(),
    severity: x["event"] === "auth.login_failed" ? "low" : "info",
    confidence: 0.95,
    summary: `${app === "magnus_ui" ? "Magnus" : "Cindertrace"} UI ${x["event"].replace("auth.", "").replaceAll("_", " ")} (${x["method"]})`,
    entities: [
      {
        type: "account",
        value: `${app}:${x["pairLabel"]}`,
        label: `${app} account ${String(x["accountLabel"]).slice(0, 8)} from ${x["sourceAddress"]}`,
      },
      { type: "service", value: app },
      ...(x["sourceAddress"] === "unverified"
        ? []
        : [{ type: "ip" as const, value: x["sourceAddress"] }]),
    ],
    attributes: safe,
    evidence: [
      {
        sourceLocator: `loki-ui:${app}:${x["eventId"]}`,
        mediaType: "application/json",
        snapshot: safe,
      },
    ],
  };
}
