import {
  decodeCursor,
  encodeCursor,
  feedPage,
  validateHiveEvent,
  type HiveEvent,
  type HiveEventSeverity,
  type Page,
} from "@hivemagnus/hive-common/events";
import { isAgentRef, isIdentifier, parseAgentRef } from "@hivemagnus/hive-common/contracts";
import { CINDERTRACE_HIVE_EVENT_TYPES } from "@cindertrace/contracts/browser";
import { getDb } from "../db/index.js";
import { HttpError } from "../middleware/error-handler.js";

/**
 * HiveEvent v1 feed for the HiveXUI inbox. Every event is derived from records Cindertrace
 * already stores: case activity (case transitions, approval decisions, containment results)
 * and containment approval requests. Nothing is written for the feed.
 */
export const HIVE_EVENT_PRODUCT = "cindertrace";
export const HIVE_EVENT_RETENTION_MS = 14 * 24 * 60 * 60 * 1000;
/** Rows read at one instant: ties at a page boundary are read whole, up to this bound. */
const MAX_ROWS_AT_INSTANT = 1000;

export { CINDERTRACE_HIVE_EVENT_TYPES };
export type CindertraceHiveEventType = (typeof CINDERTRACE_HIVE_EVENT_TYPES)[number];

/** Case activity kinds that become events. `case.updated` counts only when it closes a case. */
const ACTIVITY_TYPES: Readonly<Record<string, CindertraceHiveEventType>> = {
  "case.opened": "case.opened",
  "case.reopened": "case.reopened",
  "case.escalated": "case.severity.raised",
  "containment.admin_approve": "containment.approval.approved",
  "containment.external_approve": "containment.approval.approved",
  "containment.admin_reject": "containment.approval.rejected",
  "containment.external_reject": "containment.approval.rejected",
  "containment.succeeded": "containment.action.succeeded",
  "containment.failed": "containment.action.failed",
  "containment.unknown": "containment.action.unknown",
  "isolation.release_requested": "containment.release.requested",
  "containment.released": "containment.action.released",
};
export const HIVE_EVENT_ACTIVITY_KINDS = Object.keys(ACTIVITY_TYPES);
export const CLOSED_CASE_STATUSES = ["resolved", "false_positive"] as const;

export interface ActivityRow {
  id: string;
  caseId: string;
  kind: string;
  detailJson: string;
  createdAt: Date;
}
export interface ApprovalRow {
  id: string;
  actionId: string;
  createdAt: Date;
}
export interface CaseRow {
  id: string;
  title: string;
  severity: string;
}
export interface ActionRow {
  id: string;
  caseId: string;
  nodeId: string;
  kind: string;
}
export interface AgentEntityRow {
  caseId: string;
  canonical: string;
  aliasesJson: string;
}

/** Reads behind the feed. Every `after` read is ordered by `createdAt`, then row ID. */
export interface HiveEventStore {
  activityAt(at: Date, take: number): Promise<ActivityRow[]>;
  activityAfter(after: Date, inclusive: boolean, take: number): Promise<ActivityRow[]>;
  approvalsAt(at: Date, take: number): Promise<ApprovalRow[]>;
  approvalsAfter(after: Date, inclusive: boolean, take: number): Promise<ApprovalRow[]>;
  cases(ids: string[]): Promise<CaseRow[]>;
  actions(ids: string[]): Promise<ActionRow[]>;
  /** Action IDs of approval decisions, by decision ID. */
  decisionActions(decisionIds: string[]): Promise<Array<{ id: string; actionId: string }>>;
  caseAgents(caseIds: string[]): Promise<AgentEntityRow[]>;
}

/** Activity rows the feed serves: the mapped kinds, and `case.updated` rows that close a case. */
function activityWhere() {
  return {
    OR: [
      { kind: { in: HIVE_EVENT_ACTIVITY_KINDS } },
      {
        kind: "case.updated",
        OR: CLOSED_CASE_STATUSES.map((status) => ({
          detailJson: { contains: `"status":"${status}"` },
        })),
      },
    ],
  };
}

export function prismaHiveEventStore(): HiveEventStore {
  const db = getDb();
  const activitySelect = { id: true, caseId: true, kind: true, detailJson: true, createdAt: true } as const;
  const approvalSelect = { id: true, actionId: true, createdAt: true } as const;
  const order = [{ createdAt: "asc" as const }, { id: "asc" as const }];
  return {
    activityAt: (at, take) =>
      db.securityFusionCaseActivity.findMany({
        where: { AND: [activityWhere(), { createdAt: at }] },
        select: activitySelect,
        orderBy: order,
        take,
      }),
    activityAfter: (after, inclusive, take) =>
      db.securityFusionCaseActivity.findMany({
        where: { AND: [activityWhere(), { createdAt: inclusive ? { gte: after } : { gt: after } }] },
        select: activitySelect,
        orderBy: order,
        take,
      }),
    approvalsAt: (at, take) =>
      db.securityFusionActionApproval.findMany({
        where: { createdAt: at },
        select: approvalSelect,
        orderBy: order,
        take,
      }),
    approvalsAfter: (after, inclusive, take) =>
      db.securityFusionActionApproval.findMany({
        where: { createdAt: inclusive ? { gte: after } : { gt: after } },
        select: approvalSelect,
        orderBy: order,
        take,
      }),
    cases: (ids) =>
      ids.length
        ? db.securityFusionCase.findMany({
            where: { id: { in: ids } },
            select: { id: true, title: true, severity: true },
          })
        : Promise.resolve([]),
    actions: (ids) =>
      ids.length
        ? db.securityFusionAction.findMany({
            where: { id: { in: ids } },
            select: { id: true, caseId: true, nodeId: true, kind: true },
          })
        : Promise.resolve([]),
    decisionActions: (ids) =>
      ids.length
        ? db.securityFusionApprovalDecision.findMany({
            where: { id: { in: ids } },
            select: { id: true, actionId: true },
          })
        : Promise.resolve([]),
    caseAgents: async (caseIds) => {
      if (!caseIds.length) return [];
      const links = await db.securityFusionCaseEntity.findMany({
        where: { caseId: { in: caseIds } },
        select: { caseId: true, entityId: true },
      });
      if (!links.length) return [];
      const entities = await db.securityFusionEntity.findMany({
        where: { id: { in: [...new Set(links.map((link) => link.entityId))] }, type: "agent" },
        select: { id: true, canonical: true, aliasesJson: true },
      });
      const byId = new Map(entities.map((entity) => [entity.id, entity]));
      return links.flatMap((link) => {
        const entity = byId.get(link.entityId);
        return entity ? [{ caseId: link.caseId, canonical: entity.canonical, aliasesJson: entity.aliasesJson }] : [];
      });
    },
  };
}

/** Cindertrace case severity to HiveEvent severity. */
export function hiveSeverity(caseSeverity: string | undefined): HiveEventSeverity {
  if (caseSeverity === "critical") return "critical";
  if (caseSeverity === "high" || caseSeverity === "medium") return "warning";
  return "info";
}

type Subject = NonNullable<HiveEvent["subject"]>;

function aliases(json: string): string[] {
  try {
    const value: unknown = JSON.parse(json);
    return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
  } catch {
    return [];
  }
}

function only<T>(values: Iterable<T>): T | undefined {
  const set = new Set(values);
  return set.size === 1 ? [...set][0] : undefined;
}

/**
 * The agent a case is about, from its agent entities: the canonical `actor:<id>` and the
 * entity's `agent-ref:` and `magnus-node:` aliases. A case with several agents names none,
 * and each value is kept only when it is a valid suite identifier.
 */
export function caseAgentSubject(rows: AgentEntityRow[]): Subject | undefined {
  if (rows.length === 0) return undefined;
  const canonical = only(rows.map((row) => row.canonical));
  if (canonical === undefined) return undefined;
  const values = [canonical, ...rows.flatMap((row) => aliases(row.aliasesJson))];
  const prefixed = (prefix: string) =>
    only(values.filter((value) => value.startsWith(prefix)).map((value) => value.slice(prefix.length)));
  const actorId = prefixed("actor:");
  const agentRef = prefixed("agent-ref:");
  const nodeId = prefixed("magnus-node:") ?? (agentRef ? parseAgentRef(agentRef)?.nodeId : undefined);
  const subject: { actorId?: string; agentRef?: string; nodeId?: string } = {};
  if (isIdentifier(actorId)) subject.actorId = actorId;
  if (isAgentRef(agentRef) && (!nodeId || agentRef.startsWith(`${nodeId}~`))) subject.agentRef = agentRef;
  if (isIdentifier(nodeId)) subject.nodeId = nodeId;
  return Object.keys(subject).length ? subject : undefined;
}

/** A containment event is about its target node; the case agent stays only when it runs there. */
function actionSubject(caseSubject: Subject | undefined, action: ActionRow | undefined): Subject | undefined {
  if (!action || !isIdentifier(action.nodeId)) return caseSubject;
  const subject: { actorId?: string; agentRef?: string; nodeId?: string } = { nodeId: action.nodeId };
  if (caseSubject?.agentRef?.startsWith(`${action.nodeId}~`)) {
    subject.agentRef = caseSubject.agentRef;
    if (caseSubject.actorId) subject.actorId = caseSubject.actorId;
  } else if (caseSubject?.actorId && (!caseSubject.nodeId || caseSubject.nodeId === action.nodeId)) {
    subject.actorId = caseSubject.actorId;
  }
  return subject;
}

function detail(json: string): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(json);
    return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

function str(value: unknown): string | undefined {
  return typeof value === "string" && value ? value : undefined;
}

function clip(value: string, max: number): string {
  const clean = value.replace(/[\u0000-\u001f\u007f]+/gu, " ").trim();
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}

const ACTION_LABELS: Readonly<Record<string, string>> = {
  host_isolation: "Host isolation",
  service_restart: "Service restart",
};
function actionLabel(action: ActionRow | undefined): string {
  return (action && ACTION_LABELS[action.kind]) ?? "Containment";
}

export function caseLink(caseId: string) {
  return { product: HIVE_EVENT_PRODUCT, path: `/security-fusion/cases/${encodeURIComponent(caseId)}` };
}

interface Context {
  cases: Map<string, CaseRow>;
  actions: Map<string, ActionRow>;
  decisionActions: Map<string, string>;
  subjects: Map<string, Subject | undefined>;
}

function caseTitle(context: Context, caseId: string): string {
  return context.cases.get(caseId)?.title || "Security case";
}

function base(
  id: string,
  type: CindertraceHiveEventType,
  severity: HiveEventSeverity,
  title: string,
  summary: string,
  occurredAt: Date,
  caseId: string,
  sourceRef: string,
  subject: Subject | undefined,
): HiveEvent {
  return {
    id,
    product: HIVE_EVENT_PRODUCT,
    type,
    severity,
    title: clip(title, 200),
    summary: clip(summary, 2000),
    occurredAt: occurredAt.toISOString(),
    ...(subject ? { subject } : {}),
    link: caseLink(caseId),
    sourceRef,
  };
}

/** The event for one case activity row, or null for rows the feed does not serve. */
export function activityEvent(row: ActivityRow, context: Context): HiveEvent | null {
  const info = detail(row.detailJson);
  let type = ACTIVITY_TYPES[row.kind];
  if (row.kind === "case.updated") {
    const status = str(info["status"]);
    if (!status || !(CLOSED_CASE_STATUSES as readonly string[]).includes(status)) return null;
    type = "case.closed";
  }
  if (!type) return null;
  const caseRow = context.cases.get(row.caseId);
  const title = caseTitle(context, row.caseId);
  const caseSubject = context.subjects.get(row.caseId);
  const transition = type === "case.severity.raised" ? "severity-raised" : type.slice(type.lastIndexOf(".") + 1);
  const id =
    type === "case.opened"
      ? `cindertrace:case:${row.caseId}:opened`
      : type.startsWith("case.")
        ? `cindertrace:case:${row.caseId}:${transition}:${row.id}`
        : `cindertrace:case:${row.caseId}:containment-${transition}:${row.id}`;
  const make = (severity: HiveEventSeverity, heading: string, summary: string, subject = caseSubject) =>
    base(id, type, severity, heading, summary, row.createdAt, row.caseId, `case-activity:${row.id}`, subject);
  const severity = hiveSeverity(caseRow?.severity);
  const severityText = caseRow ? `${caseRow.severity} severity` : "unknown severity";
  switch (type) {
    case "case.opened":
      return make(severity, `Case opened: ${title}`, `A new ${severityText} security case was opened.`);
    case "case.reopened":
      return make(severity, `Case reopened: ${title}`, `New evidence reopened this ${severityText} case.`);
    case "case.severity.raised": {
      const previous = str(info["previousSeverity"]);
      return make(
        severity,
        `Case severity raised: ${title}`,
        previous && caseRow
          ? `Severity raised from ${previous} to ${caseRow.severity}.`
          : `New evidence raised this case to ${severityText}.`,
      );
    }
    case "case.closed":
      return make(
        "info",
        `Case closed: ${title}`,
        info["status"] === "false_positive" ? "The case was closed as a false positive." : "The case was resolved.",
      );
    default: {
      const actionId = str(info["actionId"]) ?? context.decisionActions.get(str(info["decisionId"]) ?? "");
      const action = actionId ? context.actions.get(actionId) : undefined;
      const label = actionLabel(action);
      const target = action ? ` on node ${action.nodeId}` : "";
      const subject = actionSubject(caseSubject, action);
      const external = row.kind.startsWith("containment.external_") ? " through the external approval adapter" : "";
      const texts: Record<string, [HiveEventSeverity, string, string]> = {
        "containment.approval.approved": ["info", `${label} approved`, `${label}${target} was approved${external} for case: ${title}.`],
        "containment.approval.rejected": ["info", `${label} rejected`, `${label}${target} was rejected${external} for case: ${title}.`],
        "containment.action.succeeded": ["info", `${label} succeeded`, `${label}${target} completed for case: ${title}.`],
        "containment.action.failed": ["critical", `${label} failed`, `${label}${target} failed for case: ${title}. Review the case.`],
        "containment.action.unknown": ["critical", `${label} outcome unknown`, `${label}${target} has an unknown outcome for case: ${title}. It is not replayed; verify the node.`],
        "containment.release.requested": ["info", "Isolation release requested", `Release of the isolation${target} was requested for case: ${title}.`],
        "containment.action.released": ["info", "Isolation released", `The isolation${target} was released for case: ${title}.`],
      };
      const text = texts[type];
      return text ? make(text[0], text[1], text[2], subject) : null;
    }
  }
}

/** The event for one containment approval request. */
export function approvalEvent(row: ApprovalRow, context: Context): HiveEvent | null {
  const action = context.actions.get(row.actionId);
  if (!action) return null;
  const label = actionLabel(action);
  return base(
    `cindertrace:containment:${row.actionId}:requested`,
    "containment.approval.requested",
    "warning",
    `${label} awaiting approval`,
    `${label} on node ${action.nodeId} is waiting for an administrator decision for case: ${caseTitle(context, action.caseId)}.`,
    row.createdAt,
    action.caseId,
    `containment-approval:${row.id}`,
    actionSubject(context.subjects.get(action.caseId), action),
  );
}

interface Position {
  time: number;
  id: string;
}

function after(event: HiveEvent, position: Position | undefined): boolean {
  if (!position) return true;
  const time = Date.parse(event.occurredAt);
  return time > position.time || (time === position.time && event.id > position.id);
}

function compare(a: HiveEvent, b: HiveEvent): number {
  const delta = Date.parse(a.occurredAt) - Date.parse(b.occurredAt);
  return delta !== 0 ? delta : a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

export function hiveEventCursor(event: HiveEvent): string {
  return encodeCursor({ t: event.occurredAt, id: event.id });
}

function readCursor(cursor: string): Position {
  let value: Record<string, string | number>;
  try {
    value = decodeCursor(cursor);
  } catch {
    throw new HttpError(400, "INVALID_CURSOR", "The cursor is not valid");
  }
  const time = typeof value["t"] === "string" ? Date.parse(value["t"]) : Number.NaN;
  if (!Number.isFinite(time) || typeof value["id"] !== "string" || !value["id"])
    throw new HttpError(400, "INVALID_CURSOR", "The cursor is not valid");
  return { time, id: value["id"] };
}

/** Rows strictly after `start` (or from it when `inclusive`), in order, with every row tied at the last instant. */
async function readSource<R extends { id: string; createdAt: Date }>(
  start: Date,
  inclusive: boolean,
  take: number,
  at: (at: Date, take: number) => Promise<R[]>,
  next: (after: Date, inclusive: boolean, take: number) => Promise<R[]>,
): Promise<R[]> {
  const rows = new Map<string, R>();
  if (!inclusive) for (const row of await at(start, MAX_ROWS_AT_INSTANT)) rows.set(row.id, row);
  const page = await next(start, inclusive, take);
  for (const row of page) rows.set(row.id, row);
  const last = page.at(-1);
  if (page.length === take && last)
    for (const row of await at(last.createdAt, MAX_ROWS_AT_INSTANT)) rows.set(row.id, row);
  return [...rows.values()];
}

export interface HiveEventFeedOptions {
  after: string | undefined;
  limit: number;
  now?: Date;
  store?: HiveEventStore;
  onInvalid?: (info: { type: string; issues: number }) => void;
}

/** One page of the feed: events strictly after the cursor, oldest first, within 14 days. */
export async function readHiveEventFeed(options: HiveEventFeedOptions): Promise<Page<HiveEvent>> {
  const store = options.store ?? prismaHiveEventStore();
  const cutoff = (options.now ?? new Date()).getTime() - HIVE_EVENT_RETENTION_MS;
  const cursor = options.after ? readCursor(options.after) : undefined;
  const position = cursor && cursor.time >= cutoff ? cursor : undefined;
  const start = new Date(position ? position.time : cutoff);
  const inclusive = !position;
  const take = options.limit + 1;
  const [activity, approvals] = await Promise.all([
    readSource(start, inclusive, take, store.activityAt, store.activityAfter),
    readSource(start, inclusive, take, store.approvalsAt, store.approvalsAfter),
  ]);
  const decisionIds = activity.flatMap((row) => {
    const id = str(detail(row.detailJson)["decisionId"]);
    return id && row.kind.startsWith("containment.") ? [id] : [];
  });
  const decisions = await store.decisionActions([...new Set(decisionIds)]);
  const actionIds = new Set([
    ...approvals.map((row) => row.actionId),
    ...decisions.map((row) => row.actionId),
    ...activity.flatMap((row) => {
      const id = str(detail(row.detailJson)["actionId"]);
      return id ? [id] : [];
    }),
  ]);
  const actions = await store.actions([...actionIds]);
  const caseIds = [...new Set([...activity.map((row) => row.caseId), ...actions.map((row) => row.caseId)])];
  const [cases, agents] = await Promise.all([store.cases(caseIds), store.caseAgents(caseIds)]);
  const agentsByCase = new Map<string, AgentEntityRow[]>();
  for (const row of agents) agentsByCase.set(row.caseId, [...(agentsByCase.get(row.caseId) ?? []), row]);
  const context: Context = {
    cases: new Map(cases.map((row) => [row.id, row])),
    actions: new Map(actions.map((row) => [row.id, row])),
    decisionActions: new Map(decisions.map((row) => [row.id, row.actionId])),
    subjects: new Map(caseIds.map((id) => [id, caseAgentSubject(agentsByCase.get(id) ?? [])])),
  };
  const events: HiveEvent[] = [];
  for (const candidate of [
    ...activity.map((row) => activityEvent(row, context)),
    ...approvals.map((row) => approvalEvent(row, context)),
  ]) {
    if (!candidate) continue;
    const result = validateHiveEvent(candidate, { strict: true });
    if (!result.ok) {
      // Log the type and issue count only; never the event content.
      (options.onInvalid ?? ((info) => console.warn(`[hive-events] dropped invalid ${info.type} event (${info.issues} issues)`)))({
        type: candidate.type,
        issues: result.issues.length,
      });
      continue;
    }
    if (Date.parse(result.value.occurredAt) >= cutoff && after(result.value, position)) events.push(result.value);
  }
  events.sort(compare);
  return feedPage(events.slice(0, take), options.limit, hiveEventCursor);
}
