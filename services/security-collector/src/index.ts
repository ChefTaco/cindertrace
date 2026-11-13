import { collectHiveSecurity } from "./hive.js";
import {
  parseUiSecurity,
  uiWindowStart,
  uiApplications,
  type UiSources,
} from "./ui-security.js";
import { createHmac, randomBytes } from "node:crypto";
import { execFile } from "node:child_process";
import { createSocket } from "node:dgram";
import {
  createReadStream,
  existsSync,
  mkdirSync,
  statSync,
  readFileSync,
  writeFileSync,
  renameSync,
} from "node:fs";
import { createInterface } from "node:readline";
import { promisify } from "node:util";
import { join } from "node:path";
import type {
  SecurityFusionEvent,
  SecurityFusionEventBatch,
  SecurityFusionSource,
  SecurityFusionSourceReport,
  SecurityFusionSourceStatus,
} from "@cindertrace/contracts";
import { securityFusionSourceSchema } from "@cindertrace/contracts";
import {
  aggregateUnifiLokiEvents,
  externalEvent,
  parseCef,
  parseDnsmasq,
  parseFlowDatagram,
  parseUnifiLokiEntry,
} from "./parsers.js";
import {
  BoundedSecurityEventQueue,
  boundedFetch,
  parseBoundedJson,
  readSecurityCollectorRuntimeConfig,
  singleFlight,
  checkpointedPoll,
  ingestRejection,
} from "./runtime-security.js";
import { fetchCompleteLokiWindow } from "./loki-query.js";
import {
  OathweaveTokenCache,
  pollAuditSource,
  readAuditExportConfig,
} from "./audit-export.js";

const runtimeConfig = readSecurityCollectorRuntimeConfig();
const auditSources = readAuditExportConfig();
const controlUrl = (
  process.env["CINDERTRACE_API_URL"] ??
  process.env["CONTROL_API_URL"] ??
  ""
).replace(/\/$/, "");
if (!controlUrl || new URL(controlUrl).protocol !== "https:")
  throw new Error("CINDERTRACE_API_URL must be HTTPS");
const ingestSecret = runtimeConfig.ingestSecret;
const collectorId =
  process.env["SECURITY_FUSION_COLLECTOR_ID"] ?? "cindertrace-collector";
const queue = new BoundedSecurityEventQueue(runtimeConfig.maxQueueEvents);
const cursors = new Map<string, string>();
const committedCursors = new Map<string, string>();
mkdirSync(process.env["SECURITY_FUSION_STATE_DIR"] ?? "state", {
  recursive: true,
  mode: 0o700,
});
const boundaryFile = join(
  process.env["SECURITY_FUSION_STATE_DIR"] ?? "state",
  "loki-boundary.json",
);
let boundary: { timestamp: string; fingerprints: string[] } | null = null;
const execFileAsync = promisify(execFile);
const sourceHealth = new Map<
  SecurityFusionSource,
  {
    status: SecurityFusionSourceStatus;
    lastEventAt?: string;
    error?: string;
  }
>();
let admittedSources: Set<SecurityFusionSource> | null = null;

function setSourceStatus(
  source: SecurityFusionSource,
  status: SecurityFusionSourceStatus,
  error?: string,
): void {
  const current = sourceHealth.get(source);
  sourceHealth.set(source, {
    ...current,
    status,
    ...(error ? { error: error.slice(0, 500) } : { error: undefined }),
  });
}

function enqueue(event: SecurityFusionEvent | null): boolean {
  if (!event) return true;
  const rejection = ingestRejection(event);
  if (rejection) {
    // Retrying cannot make this event admissible; drop it so its batch is not refused forever.
    console.error(`${event.source} event dropped before ingest: ${rejection}`);
    return true;
  }
  const currentHealth = sourceHealth.get(event.source);
  const latestEventAt =
    !currentHealth?.lastEventAt || event.observedAt > currentHealth.lastEventAt
      ? event.observedAt
      : currentHealth.lastEventAt;
  const result = queue.enqueue(event);
  if (result === "full") {
    setSourceStatus(
      event.source,
      "error",
      `collector queue reached its ${runtimeConfig.maxQueueEvents} event limit; event dropped`,
    );
    return false;
  }
  sourceHealth.set(event.source, {
    status: "healthy",
    lastEventAt: latestEventAt,
  });
  return true;
}

function recordDisplacedEvents(events: readonly SecurityFusionEvent[]): void {
  for (const event of events) {
    setSourceStatus(
      event.source,
      "error",
      `collector queue reached its ${runtimeConfig.maxQueueEvents} event limit during retry; newer event dropped`,
    );
  }
}

function request(input: string | URL, init: RequestInit = {}) {
  return boundedFetch(input, init, {
    timeoutMs: runtimeConfig.httpTimeoutMs,
    maxResponseBytes: runtimeConfig.maxResponseBytes,
  });
}

const auditTokens = new OathweaveTokenCache(request);

function signedHeaders(raw: string): Record<string, string> {
  const timestamp = new Date().toISOString();
  const nonce = randomBytes(18).toString("base64url");
  const signature = createHmac("sha256", ingestSecret)
    .update(`${collectorId}.${timestamp}.${nonce}.${raw}`)
    .digest("hex");
  return {
    "x-security-timestamp": timestamp,
    "x-security-nonce": nonce,
    "x-security-signature": signature,
    "x-security-collector-id": collectorId,
  };
}

async function flush(): Promise<void> {
  if (queue.size === 0) return;
  const pendingCheckpoints = Object.fromEntries(cursors);
  const savedCheckpoints = Object.fromEntries(committedCursors);
  const envelope = {
    schemaVersion: "1.0" as const,
    collectorId,
    sentAt: new Date().toISOString(),
    events: [],
  };
  const overhead = Math.max(
    ...[pendingCheckpoints, savedCheckpoints].map((checkpoints) =>
      Buffer.byteLength(JSON.stringify({ ...envelope, checkpoints })),
    ),
  );
  const events = queue.take(100, 262_144 - overhead + 2);
  if (!events.length)
    throw new Error(
      "Queued event exceeds the signed ingestion byte budget; checkpoint held",
    );
  const batch: SecurityFusionEventBatch = {
    ...envelope,
    events,
    checkpoints: queue.size === 0 ? pendingCheckpoints : savedCheckpoints,
  };
  const raw = JSON.stringify(batch);
  try {
    const { response } = await request(
      `${controlUrl}/api/v1/security-fusion/ingest/events`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...signedHeaders(raw),
        },
        body: raw,
      },
    );
    if (!response.ok) throw new Error(`ingest returned ${response.status}`);
    if (queue.size === 0 && batch.checkpoints) {
      for (const [source, cursor] of Object.entries(batch.checkpoints))
        committedCursors.set(source, cursor);
      if (boundary && boundary.timestamp === batch.checkpoints["unifi_ids"]) {
        const temporary = `${boundaryFile}.tmp`;
        writeFileSync(temporary, JSON.stringify(boundary), { mode: 0o600 });
        renameSync(temporary, boundaryFile);
      }
    }
  } catch (error) {
    recordDisplacedEvents(queue.requeueFront(events));
    console.error(error instanceof Error ? error.message : String(error));
  }
}

async function reportSourceStatus(): Promise<void> {
  if (sourceHealth.size === 0) return;
  const admitted = [...sourceHealth.entries()].filter(
    ([source]) => !admittedSources || admittedSources.has(source),
  );
  if (!admitted.length) return;
  const report: SecurityFusionSourceReport = {
    schemaVersion: "1.0",
    collectorId,
    sentAt: new Date().toISOString(),
    sources: admitted.map(([source, state]) => ({
      source,
      status: state.status,
      ...(state.lastEventAt ? { lastEventAt: state.lastEventAt } : {}),
      ...(committedCursors.get(source)
        ? { checkpoint: committedCursors.get(source)! }
        : {}),
      ...(state.error ? { error: state.error } : {}),
    })),
  };
  const raw = JSON.stringify(report);
  const { response } = await request(
    `${controlUrl}/api/v1/security-fusion/ingest/source-status`,
    {
      method: "POST",
      headers: { "content-type": "application/json", ...signedHeaders(raw) },
      body: raw,
    },
  );
  if (!response.ok)
    throw new Error(`source status returned ${response.status}`);
}

async function hydrateCheckpoints(): Promise<void> {
  const { response, body: rawBody } = await request(
    `${controlUrl}/api/v1/security-fusion/ingest/checkpoints`,
    {
      headers: signedHeaders(""),
    },
  );
  if (!response.ok)
    throw new Error(`checkpoint hydration returned ${response.status}`);
  const body = parseBoundedJson<{
    data?: Record<string, string | null>;
    allowedSources?: unknown;
  }>(rawBody, "checkpoint hydration");
  if (body.allowedSources !== undefined) {
    admittedSources = new Set(
      securityFusionSourceSchema.array().min(1).parse(body.allowedSources),
    );
    for (const [source, state] of sourceHealth)
      if (state.status !== "unconfigured" && !admittedSources.has(source))
        throw new Error(
          `Configured source is outside this collector's admission: ${source}`,
        );
  }
  for (const [source, checkpoint] of Object.entries(body.data ?? {})) {
    if (checkpoint) {
      cursors.set(source, checkpoint);
      committedCursors.set(source, checkpoint);
    }
  }
  try {
    const parsed: unknown = JSON.parse(readFileSync(boundaryFile, "utf8"));
    if (
      parsed &&
      typeof parsed === "object" &&
      typeof (parsed as { timestamp?: unknown }).timestamp === "string" &&
      Array.isArray((parsed as { fingerprints?: unknown }).fingerprints) &&
      (parsed as { timestamp: string }).timestamp ===
        committedCursors.get("unifi_ids")
    ) {
      boundary = parsed as typeof boundary;
    }
  } catch {
    /* Missing local boundary means safe inclusive replay. */
  }
}

function udp(
  port: number,
  parser: (buffer: Buffer, address: string) => SecurityFusionEvent | null,
): void {
  const socket = createSocket("udp4");
  socket.on("message", (message, remote) =>
    enqueue(parser(message, remote.address)),
  );
  socket.bind(port, process.env["SECURITY_FUSION_BIND"] ?? "127.0.0.1");
}

async function pollJson(
  source: "hive" | "chattermost",
  url: string | undefined,
  token: string | undefined,
  allowCursorRecovery = true,
): Promise<void> {
  if (!url || !token) return;
  const requestUrl = new URL(url);
  requestUrl.searchParams.set("limit", "500");
  const cursor = cursors.get(source);
  if (cursor) requestUrl.searchParams.set("cursor", cursor);
  const { response, body: rawBody } = await request(requestUrl, {
    headers: { authorization: `Bearer ${token}`, accept: "application/json" },
  });
  if (response.status === 410 && allowCursorRecovery) {
    const expired = parseBoundedJson<{
      earliest_available_cursor?: string | null;
      earliest_available_sequence?: number | null;
    }>(rawBody, `${source} cursor recovery`);
    const recoveryCursor =
      expired.earliest_available_cursor ??
      (expired.earliest_available_sequence === null ||
      expired.earliest_available_sequence === undefined
        ? null
        : String(expired.earliest_available_sequence - 1));
    if (!recoveryCursor)
      throw new Error(
        `${source} export cursor expired without a recovery cursor`,
      );
    cursors.set(source, recoveryCursor);
    return pollJson(source, url, token, false);
  }
  if (!response.ok)
    throw new Error(`${source} export returned ${response.status}`);
  const body = parseBoundedJson<{
    events?: Record<string, unknown>[];
    data?: Record<string, unknown>[];
    nextCursor?: string | null;
  }>(rawBody, `${source} export`);
  for (const row of body.events ?? body.data ?? [])
    if (!enqueue(externalEvent(source, row)))
      throw new Error(`${source} queue full; checkpoint held`);
  if (body.nextCursor) cursors.set(source, body.nextCursor);
}

async function pollHiveIam(): Promise<void> {
  const next = await collectHiveSecurity({
    iamUrl: process.env["HIVE_IAM_SECURITY_URL"]!,
    clientId: process.env["HIVE_IAM_SECURITY_CLIENT_ID"] ?? "security-exporter",
    secret: process.env["HIVE_IAM_SECURITY_CLIENT_SECRET"]!,
    routerUrl: process.env["HIVE_SECURITY_EXPORT_URL"],
    checkpoint: cursors.get("hive"),
    request,
    enqueue,
  });
  cursors.set("hive", next);
}

async function pollTailscale(): Promise<void> {
  const token = process.env["TAILSCALE_SECURITY_TOKEN"];
  const tailnet = process.env["TAILSCALE_TAILNET"];
  if (token && tailnet) {
    const end = new Date();
    const start = new Date(end.getTime() - 2 * 60_000);
    for (const logType of ["configuration", "network"]) {
      const url = `https://api.tailscale.com/api/v2/tailnet/${encodeURIComponent(tailnet)}/logging/${logType}?start=${encodeURIComponent(start.toISOString())}&end=${encodeURIComponent(end.toISOString())}`;
      const { response, body: rawBody } = await request(url, {
        headers: {
          authorization: `Bearer ${token}`,
          accept: "application/json",
        },
      });
      if (!response.ok)
        throw new Error(
          `Tailscale ${logType} logging returned ${response.status}`,
        );
      const body = parseBoundedJson<{ logs?: Record<string, unknown>[] }>(
        rawBody,
        `Tailscale ${logType} logging`,
      );
      for (const row of body.logs ?? [])
        enqueue(
          externalEvent("tailscale", {
            ...row,
            eventType: `tailscale.${logType}`,
          }),
        );
    }
    return;
  }
  const { stdout } = await execFileAsync("tailscale", ["status", "--json"], {
    timeout: 15_000,
    maxBuffer: 4 * 1024 * 1024,
  });
  const body = JSON.parse(stdout) as {
    Self?: Record<string, unknown>;
    Peer?: Record<string, Record<string, unknown>>;
  };
  for (const peer of [body.Self, ...Object.values(body.Peer ?? {})]) {
    if (!peer) continue;
    const stableId = String(
      peer["ID"] ??
        peer["PublicKey"] ??
        peer["DNSName"] ??
        peer["HostName"] ??
        "",
    );
    if (!stableId) continue;
    const online = Boolean(peer["Online"]);
    const ip = Array.isArray(peer["TailscaleIPs"])
      ? peer["TailscaleIPs"][0]
      : undefined;
    enqueue(
      externalEvent("tailscale", {
        id: `${stableId}:${online}:${String(peer["LastSeen"] ?? "")}`,
        timestamp: peer["LastSeen"] ?? new Date().toISOString(),
        eventType: online ? "tailscale.peer.online" : "tailscale.peer.offline",
        title: `${String(peer["HostName"] ?? peer["DNSName"] ?? stableId)} is ${online ? "online" : "offline"} on the tailnet`,
        hostName: peer["HostName"] ?? peer["DNSName"],
        ipAddress: ip,
        online,
      }),
    );
  }
}

function lokiEnvironment(name: "URL" | "QUERY" | "LIMIT"): string | undefined {
  return process.env[`LOKI_${name}`];
}

async function pollLoki(): Promise<void> {
  const baseUrl = lokiEnvironment("URL")?.replace(/\/$/u, "");
  if (!baseUrl) return;
  const credential = process.env["LOKI_READ_TOKEN"];
  if (!baseUrl.startsWith("https://") || !credential || credential.length < 40)
    throw Error("Loki requires verified HTTPS and a dedicated read credential");
  const endNs = BigInt(Date.now()) * 1_000_000n;
  const checkpoint = cursors.get("unifi_ids");
  const parsedCheckpoint =
    checkpoint && /^\d+$/u.test(checkpoint) ? BigInt(checkpoint) : null;
  const startNs =
    parsedCheckpoint === null
      ? endNs - 3n * 60n * 1_000_000_000n
      : parsedCheckpoint + 1n;
  const initialLimit = Number(lokiEnvironment("LIMIT") ?? "1000");
  const query = lokiEnvironment("QUERY");
  if (!query)
    throw new Error(
      "LOKI_QUERY must explicitly select the configured source stream",
    );
  const fetchPage = async (requestUrl: URL) => {
    const { response, body: rawBody } = await request(requestUrl, {
      headers: {
        accept: "application/json",
        authorization: `Bearer ${credential}`,
      },
    });
    if (!response.ok) throw new Error(`Loki returned ${response.status}`);
    return parseBoundedJson(rawBody, "Loki");
  };
  const boundaryEntries =
    parsedCheckpoint === null
      ? []
      : await fetchCompleteLokiWindow(
          baseUrl,
          query,
          parsedCheckpoint,
          parsedCheckpoint,
          initialLimit,
          fetchPage,
        );
  const forwardEntries = await fetchCompleteLokiWindow(
    baseUrl,
    query,
    startNs,
    endNs,
    initialLimit,
    fetchPage,
  );
  const entries = [...boundaryEntries, ...forwardEntries];
  let latestNs = parsedCheckpoint ?? startNs - 1n;
  const activeBoundary = boundary;
  const known =
    activeBoundary && activeBoundary.timestamp === checkpoint
      ? new Set(activeBoundary.fingerprints)
      : new Set<string>();
  const parsedEvents: SecurityFusionEvent[] = [];
  for (const entry of entries) {
    if (entry.timestampNs > latestNs) latestNs = entry.timestampNs;
    if (entry.timestampNs === parsedCheckpoint && known.has(entry.fingerprint))
      continue;
    const observedAt = new Date(Number(entry.timestampNs / 1_000_000n));
    parsedEvents.push(
      ...parseUnifiLokiEntry(entry.line, entry.labels, observedAt),
    );
  }
  let full = false;
  for (const event of aggregateUnifiLokiEvents(parsedEvents))
    if (!enqueue(event)) full = true;
  if (full)
    throw Error("Loki events exceeded collector queue; checkpoint held");
  if (entries.length > 0) {
    boundary = {
      timestamp: latestNs.toString(),
      fingerprints: entries
        .filter((entry) => entry.timestampNs === latestNs)
        .map((entry) => entry.fingerprint),
    };
    for (const source of ["unifi_dns", "unifi_ids", "netflow"] as const) {
      cursors.set(source, latestNs.toString());
    }
  }
}

const uiSources: UiSources = JSON.parse(
  process.env["UI_SECURITY_SOURCES_JSON"] ?? "{}",
) as UiSources;
const enabledUiSources = [...new Set(Object.values(uiApplications))].filter(
  (source) => Array.isArray(uiSources[source]) && uiSources[source]!.length > 0,
);
const uiLogApplications = Object.entries(uiApplications)
  .filter(([, source]) => enabledUiSources.includes(source))
  .map(([application]) => application)
  .join("|");
async function pollUiSecurity(): Promise<void> {
  const base = lokiEnvironment("URL")?.replace(/\/$/u, "");
  const credential = process.env["LOKI_READ_TOKEN"];
  if (!base?.startsWith("https://") || !credential)
    throw Error("UI audit requires the authenticated Loki read boundary");
  const end = BigInt(Date.now()) * 1_000_000n;
  const start = uiWindowStart(
    enabledUiSources.map((source) => cursors.get(source)),
    end,
  );
  // Inclusive replay keeps same-timestamp boundaries complete; event UUIDs deduplicate.
  const entries = await fetchCompleteLokiWindow(
    base,
    `{job="syslog",syslog_app=~"${uiLogApplications}"}`,
    start,
    end,
    1000,
    async (url) => {
      const { response, body } = await request(url, {
        headers: {
          authorization: `Bearer ${credential}`,
          accept: "application/json",
        },
      });
      if (!response.ok) throw Error(`UI audit Loki HTTP ${response.status}`);
      return parseBoundedJson(body, "UI audit Loki");
    },
  );
  // Parse the whole page before enqueueing; malformed trusted input holds the cursor.
  const events = entries.map((entry) =>
    parseUiSecurity(entry.line, entry.labels, uiSources),
  );
  for (const event of events)
    if (!enqueue(event)) throw Error("UI audit queue full; checkpoint held");
  if (entries.length)
    for (const source of enabledUiSources)
      cursors.set(source, entries.at(-1)!.timestampNs.toString());
}

function followDnsLog(path: string): void {
  if (!existsSync(path)) return;
  let offset = statSync(path).size;
  setInterval(() => {
    if (!existsSync(path)) return;
    const size = statSync(path).size;
    if (size < offset) offset = 0;
    if (size === offset) return;
    const stream = createReadStream(path, { start: offset, end: size - 1 });
    offset = size;
    const lines = createInterface({ input: stream });
    lines.on("line", (line) => enqueue(parseDnsmasq(line)));
  }, 5_000).unref();
}

// Loki polling needs no UDP listener when syslog terminates at an external collector.
if (process.env["SECURITY_FUSION_UDP_ENABLED"] === "true") {
  udp(Number(process.env["UNIFI_CEF_PORT"] ?? 5514), (buffer) =>
    parseCef(buffer.toString("utf8")),
  );
  udp(Number(process.env["NETFLOW_PORT"] ?? 2055), parseFlowDatagram);
}
if (process.env["UNIFI_DNS_LOG_PATH"])
  followDnsLog(process.env["UNIFI_DNS_LOG_PATH"]);
const flushSingleFlight = singleFlight(flush);
setInterval(() => {
  void flushSingleFlight().catch((error: unknown) => {
    console.error(
      `collector flush failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  });
}, 2_000);
function runPoll(
  label: string,
  sources: SecurityFusionSource[],
  poll: () => Promise<void>,
): Promise<void> {
  return poll()
    .then(() => {
      for (const source of sources) setSourceStatus(source, "healthy");
    })
    .catch((error: unknown) => {
      const message = error instanceof Error ? error.message : String(error);
      for (const source of sources) setSourceStatus(source, "error", message);
      console.error(`${label}: ${message}`);
    });
}

for (const source of enabledUiSources) setSourceStatus(source, "configured");
setSourceStatus(
  "unifi_ids",
  process.env["SECURITY_FUSION_UDP_ENABLED"] === "true" ||
    runtimeConfig.lokiSourcesEnabled
    ? "configured"
    : "unconfigured",
);
setSourceStatus(
  "netflow",
  process.env["SECURITY_FUSION_UDP_ENABLED"] === "true" ||
    runtimeConfig.lokiSourcesEnabled
    ? "configured"
    : "unconfigured",
);
setSourceStatus(
  "unifi_dns",
  process.env["UNIFI_DNS_LOG_PATH"] || runtimeConfig.lokiSourcesEnabled
    ? "configured"
    : "unconfigured",
);
setSourceStatus(
  "tailscale",
  process.env["TAILSCALE_SECURITY_TOKEN"] ||
    process.env["TAILSCALE_LOCAL_ENABLED"] === "true"
    ? "configured"
    : "unconfigured",
);
setSourceStatus(
  "hive",
  process.env["HIVE_IAM_SECURITY_URL"] ||
    process.env["HIVE_SECURITY_EXPORT_URL"]
    ? "configured"
    : "unconfigured",
);
for (const { source } of auditSources ?? [])
  setSourceStatus(source, "configured");
setSourceStatus(
  "chattermost",
  process.env["CHATTERMOST_SECURITY_EXPORT_URL"]
    ? "configured"
    : "unconfigured",
);

async function pollSources(): Promise<void> {
  const work: Promise<void>[] = [];
  if (
    process.env["TAILSCALE_SECURITY_TOKEN"] ||
    process.env["TAILSCALE_LOCAL_ENABLED"] === "true"
  )
    work.push(runPoll("tailscale poll failed", ["tailscale"], pollTailscale));
  if (runtimeConfig.lokiSourcesEnabled) {
    work.push(
      runPoll(
        "Loki poll failed",
        ["unifi_dns", "unifi_ids", "netflow"],
        pollLoki,
      ),
    );
  }
  if (enabledUiSources.length)
    work.push(
      runPoll("UI audit poll failed", enabledUiSources, pollUiSecurity),
    );
  const hivePolls: Array<() => Promise<void>> = [];
  if (
    process.env["HIVE_IAM_SECURITY_URL"] &&
    process.env["HIVE_IAM_SECURITY_CLIENT_SECRET"]
  )
    hivePolls.push(pollHiveIam);
  if (process.env["HIVE_SECURITY_EXPORT_TOKEN"])
    throw new Error(
      "Hive static export credentials are retired; configure OAuth client credentials",
    );
  if (hivePolls.length > 0) {
    work.push(
      runPoll("Hive security poll failed", ["hive"], async () => {
        await Promise.all(hivePolls.map((poll) => poll()));
      }),
    );
  }
  if (
    process.env["CHATTERMOST_SECURITY_EXPORT_URL"] &&
    process.env["CHATTERMOST_SECURITY_EXPORT_TOKEN"]
  ) {
    work.push(
      runPoll("ChatterMost export poll failed", ["chattermost"], () =>
        pollJson(
          "chattermost",
          process.env["CHATTERMOST_SECURITY_EXPORT_URL"],
          process.env["CHATTERMOST_SECURITY_EXPORT_TOKEN"],
        ),
      ),
    );
  }
  // Each product polls independently; one failing source never holds the others.
  for (const config of auditSources ?? [])
    work.push(
      runPoll(`${config.source} audit export poll failed`, [config.source], () =>
        pollAuditSource({
          config,
          tokens: auditTokens,
          cursor: cursors.get(config.source),
          setCursor: (cursor) => cursors.set(config.source, cursor),
          request,
          enqueue,
        }),
      ),
    );
  await Promise.all(work);
  await reportSourceStatus().catch((error: unknown) => {
    console.error(
      `source status report failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  });
}

const pollSourcesSingleFlight = singleFlight(
  checkpointedPoll(hydrateCheckpoints, pollSources),
);
setInterval(() => {
  void pollSourcesSingleFlight().catch((error: unknown) => {
    console.error(
      `collector poll failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  });
}, 60_000);
console.log("cindertrace-collector started");
void pollSourcesSingleFlight().catch((error: unknown) =>
  console.error(error instanceof Error ? error.message : String(error)),
);
