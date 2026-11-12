import { readFileSync } from "node:fs";
import {
  agentActorIdSchema,
  agentEntityValue,
  agentRefSchema,
  hiveAuditExportPageSchema,
  hiveAuditProductSchema,
  hiveAuditRecordSchema,
  magnusNodeIdSchema,
  type HiveAuditProduct,
  type HiveAuditRecord,
  type SecurityFusionEntityRef,
  type SecurityFusionEvent,
  type SecurityFusionSeverity,
} from "@cindertrace/contracts";
import { eventId } from "./parsers.js";
import {
  parseBoundedJson,
  type BoundedFetchResult,
} from "./runtime-security.js";

/**
 * Pull collection of HiveAuditRecord v1 from suite products'
 * `GET <api>/v1/audit/export?after=<cursor>&limit=<n>`, authenticated with an
 * Oathweave client-credentials token. Errors name sources, statuses and field
 * paths only: record contents and credentials never reach a log line.
 */

export type Request = (
  url: string | URL,
  init?: RequestInit,
) => Promise<BoundedFetchResult>;

export interface ClientCredentials {
  tokenUrl: string;
  clientId: string;
  clientSecret: string;
}

export interface AuditSourceConfig {
  source: HiveAuditProduct;
  url: string;
  audience: string;
  scope: string;
  credentials: ClientCredentials;
}

export const AUDIT_EXPORT_PAGE_LIMIT = 200;
export const AUDIT_EXPORT_MAX_PAGES_PER_POLL = 25;

const ENV = {
  sources: "SECURITY_COLLECTOR_AUDIT_SOURCES_JSON",
  oathweaveUrl: "SECURITY_COLLECTOR_AUDIT_OATHWEAVE_URL",
  clientId: "SECURITY_COLLECTOR_AUDIT_CLIENT_ID",
  clientSecret: "SECURITY_COLLECTOR_AUDIT_CLIENT_SECRET",
  clientSecretFile: "SECURITY_COLLECTOR_AUDIT_CLIENT_SECRET_FILE",
} as const;

function httpsUrl(name: string, value: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be an HTTPS URL`);
  }
  if (url.protocol !== "https:" || url.username || url.password)
    throw new Error(`${name} must be an HTTPS URL without embedded credentials`);
  return url;
}

function text(value: unknown, name: string, max = 512): string {
  if (typeof value !== "string" || !value.trim() || value.length > max)
    throw new Error(`${name} must be a non-empty string`);
  return value.trim();
}

/** `<oathweave>/api/v1/oauth/token`, accepting a base that already ends in `/api/v1`. */
export function oathweaveTokenUrl(base: string): string {
  const trimmed = httpsUrl(ENV.oathweaveUrl, base).href.replace(/\/+$/, "");
  return `${trimmed.endsWith("/api/v1") ? trimmed : `${trimmed}/api/v1`}/oauth/token`;
}

/**
 * Read `SECURITY_COLLECTOR_AUDIT_SOURCES_JSON` and the Oathweave client
 * settings. Returns null when no audit source is configured. Each source may
 * name its own `clientId` and `clientSecretFile`, because an Oathweave machine
 * client issues tokens for one audience.
 */
export function readAuditExportConfig(
  env: NodeJS.ProcessEnv = process.env,
  readFile: (path: string) => string = (path) => readFileSync(path, "utf8"),
): AuditSourceConfig[] | null {
  const raw = env[ENV.sources]?.trim();
  if (!raw) {
    if (env[ENV.clientSecret] || env[ENV.clientSecretFile])
      throw new Error(`Audit export credentials require ${ENV.sources}`);
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`${ENV.sources} must be a JSON array`);
  }
  if (!Array.isArray(parsed) || parsed.length === 0)
    throw new Error(`${ENV.sources} must be a non-empty JSON array`);
  const secretFrom = (file: string | undefined, inline: string | undefined, label: string) => {
    if (file && inline)
      throw new Error(`${label}: set the client secret or its file, not both`);
    const secret = file ? readFile(file).trim() : inline?.trim();
    if (!secret) throw new Error(`${label}: the Oathweave client secret is missing`);
    return secret;
  };
  let shared: ClientCredentials | null = null;
  const sharedCredentials = (): ClientCredentials => {
    if (shared) return shared;
    const base = env[ENV.oathweaveUrl];
    if (!base) throw new Error(`${ENV.oathweaveUrl} is required for audit export`);
    shared = {
      tokenUrl: oathweaveTokenUrl(base),
      clientId: text(env[ENV.clientId], ENV.clientId, 200),
      clientSecret: secretFrom(env[ENV.clientSecretFile], env[ENV.clientSecret], ENV.clientId),
    };
    return shared;
  };
  const seen = new Set<string>();
  return parsed.map((entry, index) => {
    const label = `${ENV.sources}[${index}]`;
    if (!entry || typeof entry !== "object" || Array.isArray(entry))
      throw new Error(`${label} must be an object`);
    const item = entry as Record<string, unknown>;
    const source = hiveAuditProductSchema.safeParse(item["source"]);
    if (!source.success)
      throw new Error(`${label}.source must be one of ${hiveAuditProductSchema.options.join(", ")}`);
    if (seen.has(source.data)) throw new Error(`${label}.source is configured twice`);
    seen.add(source.data);
    const url = httpsUrl(`${label}.url`, text(item["url"], `${label}.url`, 2000));
    const audience = text(item["audience"], `${label}.audience`, 200);
    const scope =
      item["scope"] === undefined
        ? `${source.data}:audit:read`
        : text(item["scope"], `${label}.scope`, 1000);
    let credentials: ClientCredentials;
    if (item["clientId"] !== undefined || item["clientSecretFile"] !== undefined) {
      const base = env[ENV.oathweaveUrl];
      if (!base) throw new Error(`${ENV.oathweaveUrl} is required for audit export`);
      credentials = {
        tokenUrl: oathweaveTokenUrl(base),
        clientId: text(item["clientId"], `${label}.clientId`, 200),
        clientSecret: secretFrom(
          text(item["clientSecretFile"], `${label}.clientSecretFile`, 1000),
          undefined,
          label,
        ),
      };
    } else credentials = sharedCredentials();
    return { source: source.data, url: url.href, audience, scope, credentials };
  });
}

interface CachedToken {
  token: string;
  refreshAt: number;
}

function jwtAudiences(token: string): string[] | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8")) as {
      aud?: unknown;
    };
    if (typeof payload.aud === "string") return [payload.aud];
    if (Array.isArray(payload.aud)) return payload.aud.filter((x): x is string => typeof x === "string");
    return null;
  } catch {
    return null;
  }
}

/**
 * Client-credentials tokens cached per client, audience and scope until shortly
 * before they expire (a fifth of the lifetime, at most one minute).
 */
export class OathweaveTokenCache {
  readonly #cache = new Map<string, CachedToken>();
  readonly #pending = new Map<string, Promise<string>>();

  public constructor(
    private readonly request: Request,
    private readonly now: () => number = () => Date.now(),
  ) {}

  #key(credentials: ClientCredentials, audience: string, scope: string): string {
    return JSON.stringify([credentials.tokenUrl, credentials.clientId, audience, scope]);
  }

  public async token(credentials: ClientCredentials, audience: string, scope: string): Promise<string> {
    const key = this.#key(credentials, audience, scope);
    const cached = this.#cache.get(key);
    if (cached && this.now() < cached.refreshAt) return cached.token;
    const pending = this.#pending.get(key);
    if (pending) return pending;
    const next = this.#fetch(credentials, audience, scope)
      .then((value) => {
        this.#cache.set(key, value);
        return value.token;
      })
      .finally(() => this.#pending.delete(key));
    this.#pending.set(key, next);
    return next;
  }

  public invalidate(credentials: ClientCredentials, audience: string, scope: string): void {
    this.#cache.delete(this.#key(credentials, audience, scope));
  }

  async #fetch(credentials: ClientCredentials, audience: string, scope: string): Promise<CachedToken> {
    const { response, body } = await this.request(credentials.tokenUrl, {
      method: "POST",
      redirect: "error",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
      },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: credentials.clientId,
        client_secret: credentials.clientSecret,
        scope,
        audience,
      }),
    });
    if (!response.ok) throw new Error(`Oathweave token endpoint returned ${response.status}`);
    const value = parseBoundedJson<{ access_token?: unknown; expires_in?: unknown }>(body, "Oathweave token");
    if (typeof value.access_token !== "string" || !value.access_token)
      throw new Error("Oathweave token response is incomplete");
    const audiences = jwtAudiences(value.access_token);
    if (audiences && !audiences.includes(audience))
      throw new Error(`Oathweave token audience does not include ${audience}`);
    const lifetime =
      typeof value.expires_in === "number" && Number.isFinite(value.expires_in) && value.expires_in > 0
        ? value.expires_in
        : 300;
    const skew = Math.min(60, lifetime / 5);
    return { token: value.access_token, refreshAt: this.now() + (lifetime - skew) * 1000 };
  }
}

// --- Mapping ---

const productLabel: Record<HiveAuditProduct, string> = {
  hivemem: "HiveMem",
  hiveskills: "HiveSkills",
  ardentstudio: "ArdentStudio",
  embermend: "Embermend",
};

const CREDENTIAL_TERMS = new Set([
  "credential", "credentials", "secret", "secrets", "token", "tokens", "key", "keys",
  "apikey", "password", "passwords", "passkey", "mfa", "totp", "certificate", "cert",
]);
const PERMISSION_TERMS = new Set([
  "permission", "permissions", "role", "roles", "grant", "grants", "acl", "policy",
  "policies", "scope", "scopes", "access", "share", "member", "members", "membership",
  "privilege", "privileges", "admin", "owner", "ownership",
]);
const DELETE_TERMS = new Set([
  "delete", "deleted", "remove", "removed", "purge", "purged", "destroy", "destroyed",
  "erase", "wipe", "revoke", "revoked", "forget", "unshare",
]);
const READ_TERMS = new Set([
  "read", "list", "get", "view", "search", "query", "fetch", "download", "export",
  "recall", "lookup", "login", "signin",
]);

const severityOrder: SecurityFusionSeverity[] = ["info", "low", "medium", "high", "critical"];

/**
 * Severity from the action and outcome (documented in docs/INTEGRATIONS.md):
 * credential or permission changes are high, deletes medium, reads info and
 * other changes low. A failure raises severity one step, to at least medium.
 */
export function auditSeverity(action: string, outcome: HiveAuditRecord["outcome"]): SecurityFusionSeverity {
  const terms = action.split(/[._-]/);
  const has = (set: Set<string>) => terms.some((term) => set.has(term));
  let base: SecurityFusionSeverity;
  if (has(CREDENTIAL_TERMS) || has(PERMISSION_TERMS)) base = "high";
  else if (has(DELETE_TERMS)) base = "medium";
  else if (has(READ_TERMS)) base = "info";
  else base = "low";
  if (outcome !== "failure") return base;
  const raised = severityOrder[Math.min(severityOrder.indexOf(base) + 1, severityOrder.length - 1)]!;
  return severityOrder.indexOf(raised) < 2 ? "medium" : raised;
}

function valid(schema: { safeParse(value: unknown): { success: boolean } }, value: string | undefined) {
  return value !== undefined && schema.safeParse(value).success ? value : undefined;
}

/** Map one HiveAuditRecord v1 to a Cindertrace event. */
export function auditRecordEvent(record: HiveAuditRecord): SecurityFusionEvent {
  const source = record.product;
  const subjectActorId = valid(agentActorIdSchema, record.subject?.actorId);
  const subjectAgentRef = valid(agentRefSchema, record.subject?.agentRef);
  const subjectNodeId = valid(magnusNodeIdSchema, record.subject?.nodeId);
  const label = record.actor.displayName?.trim().slice(0, 160) || undefined;
  const entities: SecurityFusionEntityRef[] = [];
  const agentValues = new Set<string>();
  const addAgent = (value: string) => {
    if (agentValues.has(value)) return;
    agentValues.add(value);
    entities.push({ type: "agent", value });
  };
  if (record.actor.type === "user")
    entities.push({ type: "user", value: record.actor.id, ...(label ? { label } : {}) });
  else if (record.actor.type === "service")
    entities.push({ type: "service", value: record.actor.id, ...(label ? { label } : {}) });
  else if (record.actor.type === "agent") {
    if (agentActorIdSchema.safeParse(record.actor.id).success)
      addAgent(agentEntityValue.actor(record.actor.id));
    else entities.push({ type: "account", value: record.actor.id, ...(label ? { label } : {}) });
  }
  // The subject names the agent the action concerns, as other agent entities do.
  if (subjectActorId) addAgent(agentEntityValue.actor(subjectActorId));
  else if (subjectAgentRef) addAgent(agentEntityValue.agentRef(subjectAgentRef));
  const actorName = label ?? record.actor.id;
  const target =
    record.target?.type || record.target?.id
      ? ` on ${[record.target.type, record.target.id].filter(Boolean).join(" ")}`
      : "";
  return {
    schemaVersion: "1.0",
    eventId: eventId(source, record.id),
    source,
    sourceEventId: record.id,
    kind: `${source}.${record.action}`.slice(0, 160),
    observedAt: new Date(record.occurredAt).toISOString(),
    severity: auditSeverity(record.action, record.outcome),
    confidence: 0.9,
    summary:
      `${productLabel[source]} ${record.action} by ${record.actor.type} ${actorName}${target}` +
      (record.outcome === "failure" ? " failed" : ""),
    entities,
    attributes: {
      auditSchema: "HiveAuditRecord/v1",
      product: source,
      action: record.action,
      outcome: record.outcome,
      actor: record.actor,
      ...(record.target ? { target: record.target } : {}),
      // Agent identity attributes read by the API; values are used exactly as sent.
      ...(subjectActorId ? { actorId: subjectActorId } : {}),
      ...(subjectAgentRef ? { agentRef: subjectAgentRef } : {}),
      ...(subjectNodeId ? { nodeId: subjectNodeId } : {}),
      details: record.details,
    },
    evidence: [{ sourceLocator: record.id, mediaType: "application/json" }],
  };
}

function issuePaths(error: { issues: Array<{ path: PropertyKey[] }> }): string {
  return [...new Set(error.issues.map((issue) => issue.path.map(String).join(".") || "(record)"))]
    .slice(0, 8)
    .join(", ");
}

/**
 * Read pages strictly after the source's checkpoint until caught up (an empty
 * page with `nextCursor: null`) or the per-poll page budget is spent. A page
 * with records carries its last record's cursor; the last non-null cursor is
 * the checkpoint and is polled again next round. Each page is validated whole before any of it
 * is queued; `setCursor` advances only after its events are queued, so a
 * failure or a full queue holds the checkpoint at the last complete page.
 */
export async function pollAuditSource(options: {
  config: AuditSourceConfig;
  tokens: OathweaveTokenCache;
  cursor: string | undefined;
  setCursor: (cursor: string) => void;
  request: Request;
  enqueue: (event: SecurityFusionEvent) => boolean;
  pageLimit?: number;
  maxPages?: number;
}): Promise<void> {
  const { config, tokens, request } = options;
  const { source } = config;
  let cursor = options.cursor;
  const maxPages = options.maxPages ?? AUDIT_EXPORT_MAX_PAGES_PER_POLL;
  for (let page = 0; page < maxPages; page++) {
    const url = new URL(config.url);
    url.searchParams.set("limit", String(options.pageLimit ?? AUDIT_EXPORT_PAGE_LIMIT));
    if (cursor) url.searchParams.set("after", cursor);
    else url.searchParams.delete("after");
    let result: BoundedFetchResult | undefined;
    for (let attempt = 0; attempt < 2; attempt++) {
      const token = await tokens.token(config.credentials, config.audience, config.scope);
      result = await request(url, {
        redirect: "error",
        headers: { authorization: `Bearer ${token}`, accept: "application/json" },
      });
      if (result.response.status !== 401) break;
      // The product refused a cached token: fetch a fresh one and retry once.
      tokens.invalidate(config.credentials, config.audience, config.scope);
    }
    if (!result!.response.ok)
      throw new Error(`${source} audit export returned ${result!.response.status}`);
    const body = hiveAuditExportPageSchema.safeParse(
      parseBoundedJson<unknown>(result!.body, `${source} audit export`),
    );
    if (!body.success)
      throw new Error(`${source} audit export page is malformed (${issuePaths(body.error)})`);
    const ids = new Set<string>();
    const events = body.data.data.flatMap((row, index) => {
      const record = hiveAuditRecordSchema.safeParse(row);
      if (!record.success)
        throw new Error(
          `${source} audit export record ${index} is not HiveAuditRecord v1 (${issuePaths(record.error)}); checkpoint held`,
        );
      if (record.data.product !== source)
        throw new Error(`${source} audit export record ${index} names another product; checkpoint held`);
      // Safety net: a record repeated within one page is queued once.
      if (ids.has(record.data.id)) return [];
      ids.add(record.data.id);
      return [auditRecordEvent(record.data)];
    });
    for (const event of events)
      if (!options.enqueue(event)) throw new Error(`${source} audit queue full; checkpoint held`);
    const next = body.data.nextCursor;
    if (!next || next === cursor || events.length === 0) {
      if (next && next !== cursor) options.setCursor(next);
      return;
    }
    cursor = next;
    options.setCursor(next);
  }
}
