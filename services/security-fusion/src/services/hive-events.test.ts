import { describe, expect, it, vi } from "vitest";
import { validateHiveEvent } from "@hivemagnus/hive-common/contracts";
import { decodeCursor, encodeCursor } from "@hivemagnus/hive-common/events";
import { hiveEventPageSchema } from "@cindertrace/contracts/browser";

vi.mock("../db/index.js", () => ({
  getDb: () => {
    throw new Error("the feed tests use an in-memory store");
  },
}));
const {
  caseAgentSubject,
  hiveSeverity,
  readHiveEventFeed,
  HIVE_EVENT_ACTIVITY_KINDS,
  CLOSED_CASE_STATUSES,
} = await import("./hive-events.js");
type Store = import("./hive-events.js").HiveEventStore;
type ActivityRow = import("./hive-events.js").ActivityRow;
type ApprovalRow = import("./hive-events.js").ApprovalRow;

const NOW = new Date("2026-11-12T12:00:00.000Z");
const at = (minutesAgo: number) => new Date(NOW.getTime() - minutesAgo * 60_000);
const DAY = 24 * 60;

function served(row: ActivityRow): boolean {
  if (HIVE_EVENT_ACTIVITY_KINDS.includes(row.kind)) return true;
  return (
    row.kind === "case.updated" &&
    CLOSED_CASE_STATUSES.some((status) => row.detailJson.includes(`"status":"${status}"`))
  );
}

function ordered<R extends { id: string; createdAt: Date }>(rows: R[]): R[] {
  return [...rows].sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime() || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

function memoryStore(input: {
  activity?: ActivityRow[];
  approvals?: ApprovalRow[];
  agents?: Array<{ caseId: string; canonical: string; aliasesJson: string }>;
}): Store {
  const activity = ordered((input.activity ?? []).filter(served));
  const approvals = ordered(input.approvals ?? []);
  const window = <R extends { createdAt: Date }>(rows: R[]) => ({
    at: async (time: Date, take: number) => rows.filter((row) => row.createdAt.getTime() === time.getTime()).slice(0, take),
    after: async (time: Date, inclusive: boolean, take: number) =>
      rows
        .filter((row) => (inclusive ? row.createdAt >= time : row.createdAt > time))
        .slice(0, take),
  });
  const a = window(activity);
  const p = window(approvals);
  const cases = [
    { id: "case-a", title: "Credential abuse on app-1", severity: "critical" },
    { id: "case-b", title: "DNS egress from node-b", severity: "medium" },
    { id: "case-c", title: "Drift on node-c", severity: "low" },
  ];
  const actions = [
    { id: "action-1", caseId: "case-a", nodeId: "node-a", kind: "host_isolation" },
    { id: "action-2", caseId: "case-b", nodeId: "node-b", kind: "service_restart" },
  ];
  return {
    activityAt: a.at,
    activityAfter: a.after,
    approvalsAt: p.at,
    approvalsAfter: p.after,
    cases: async (ids) => cases.filter((row) => ids.includes(row.id)),
    actions: async (ids) => actions.filter((row) => ids.includes(row.id)),
    decisionActions: async (ids) =>
      [{ id: "decision-1", actionId: "action-1" }].filter((row) => ids.includes(row.id)),
    caseAgents: async (ids) => (input.agents ?? []).filter((row) => ids.includes(row.caseId)),
  };
}

const activityRows: ActivityRow[] = [
  { id: "act-01", caseId: "case-a", kind: "case.opened", detailJson: "{}", createdAt: at(120) },
  { id: "act-02", caseId: "case-a", kind: "evidence.merged", detailJson: "{}", createdAt: at(110) },
  { id: "act-03", caseId: "case-b", kind: "case.opened", detailJson: "{}", createdAt: at(100) },
  { id: "act-04", caseId: "case-b", kind: "case.escalated", detailJson: '{"previousSeverity":"low"}', createdAt: at(90) },
  { id: "act-05", caseId: "case-a", kind: "containment.admin_approve", detailJson: '{"decisionId":"decision-1"}', createdAt: at(80) },
  { id: "act-06", caseId: "case-a", kind: "containment.succeeded", detailJson: '{"actionId":"action-1"}', createdAt: at(70) },
  { id: "act-07", caseId: "case-a", kind: "isolation.release_requested", detailJson: '{"actionId":"action-1"}', createdAt: at(60) },
  { id: "act-08", caseId: "case-a", kind: "containment.released", detailJson: '{"actionId":"action-1"}', createdAt: at(50) },
  { id: "act-09", caseId: "case-b", kind: "containment.external_reject", detailJson: '{"decisionId":"unknown"}', createdAt: at(40) },
  { id: "act-10", caseId: "case-b", kind: "containment.failed", detailJson: '{"actionId":"action-2"}', createdAt: at(30) },
  { id: "act-11", caseId: "case-b", kind: "containment.unknown", detailJson: '{"actionId":"action-2"}', createdAt: at(30) },
  { id: "act-12", caseId: "case-b", kind: "case.updated", detailJson: '{"assignedTo":"someone"}', createdAt: at(20) },
  { id: "act-13", caseId: "case-b", kind: "case.updated", detailJson: '{"status":"false_positive"}', createdAt: at(20) },
  { id: "act-14", caseId: "case-c", kind: "case.reopened", detailJson: "{}", createdAt: at(10) },
  { id: "act-15", caseId: "case-a", kind: "case.updated", detailJson: '{"status":"resolved"}', createdAt: at(5) },
];
const approvalRows: ApprovalRow[] = [
  { id: "approval-1", actionId: "action-1", createdAt: at(85) },
  { id: "approval-2", actionId: "action-2", createdAt: at(30) },
];
const agents = [
  { caseId: "case-a", canonical: "actor:scout", aliasesJson: '["actor:scout","magnus-node:node-a","agent-ref:node-a~default"]' },
  { caseId: "case-b", canonical: "actor:one", aliasesJson: "[]" },
  { caseId: "case-b", canonical: "actor:two", aliasesJson: "[]" },
];
const store = memoryStore({ activity: activityRows, approvals: approvalRows, agents });

async function readAll(limit: number, s: Store = store) {
  const events = [];
  let after: string | undefined;
  for (let pages = 0; pages < 100; pages++) {
    const page = await readHiveEventFeed({ after, limit, now: NOW, store: s });
    events.push(...page.data);
    if (page.nextCursor === null) return { events, pages: pages + 1 };
    after = page.nextCursor;
  }
  throw new Error("feed did not finish");
}

describe("Cindertrace HiveEvent feed", () => {
  it("serves notable case and containment records oldest first", async () => {
    const page = await readHiveEventFeed({ after: undefined, limit: 50, now: NOW, store });
    expect(page.nextCursor).toBeNull();
    expect(page.data.map((event) => event.type)).toEqual([
      "case.opened",
      "case.opened",
      "case.severity.raised",
      "containment.approval.requested",
      "containment.approval.approved",
      "containment.action.succeeded",
      "containment.release.requested",
      "containment.action.released",
      "containment.approval.rejected",
      "containment.action.failed",
      "containment.action.unknown",
      "containment.approval.requested",
      "case.closed",
      "case.reopened",
      "case.closed",
    ]);
    const times = page.data.map((event) => Date.parse(event.occurredAt));
    expect(times).toEqual([...times].sort((a, b) => a - b));
    expect(hiveEventPageSchema.safeParse(page).success).toBe(true);
  });

  it("validates every served event strictly", async () => {
    const { events } = await readAll(3);
    expect(events.length).toBe(15);
    for (const event of events) expect(validateHiveEvent(event, { strict: true })).toMatchObject({ ok: true });
  });

  it("maps severities, links and agent subjects", async () => {
    const { events } = await readAll(50);
    const byId = new Map(events.map((event) => [event.id, event]));
    const opened = byId.get("cindertrace:case:case-a:opened")!;
    expect(opened).toMatchObject({
      product: "cindertrace",
      severity: "critical",
      link: { product: "cindertrace", path: "/security-fusion/cases/case-a" },
      subject: { actorId: "scout", agentRef: "node-a~default", nodeId: "node-a" },
      sourceRef: "case-activity:act-01",
    });
    const raised = events.find((event) => event.type === "case.severity.raised")!;
    expect(raised.severity).toBe("warning");
    expect(raised.summary).toBe("Severity raised from low to medium.");
    // A case with two agents names none.
    expect(raised.subject).toBeUndefined();
    const reopened = events.find((event) => event.type === "case.reopened")!;
    expect(reopened.severity).toBe("info");
    const requested = byId.get("cindertrace:containment:action-1:requested")!;
    expect(requested).toMatchObject({ severity: "warning", title: "Host isolation awaiting approval", link: { path: "/security-fusion/cases/case-a" } });
    const approved = events.find((event) => event.type === "containment.approval.approved")!;
    expect(approved.summary).toContain("Host isolation on node node-a was approved");
    expect(approved.subject).toEqual({ nodeId: "node-a", agentRef: "node-a~default", actorId: "scout" });
    const failed = events.find((event) => event.type === "containment.action.failed")!;
    expect(failed).toMatchObject({ severity: "critical", subject: { nodeId: "node-b" } });
    expect(events.find((event) => event.type === "containment.action.unknown")!.severity).toBe("critical");
    const closed = events.filter((event) => event.type === "case.closed");
    expect(closed.map((event) => event.summary)).toEqual([
      "The case was closed as a false positive.",
      "The case was resolved.",
    ]);
    expect(closed.every((event) => event.severity === "info")).toBe(true);
    expect(hiveSeverity("high")).toBe("warning");
    expect(hiveSeverity("info")).toBe("info");
  });

  it("round-trips the cursor through every page size without gaps or repeats", async () => {
    const all = (await readAll(200)).events.map((event) => event.id);
    for (const limit of [1, 2, 3, 7]) {
      const { events, pages } = await readAll(limit);
      expect(events.map((event) => event.id)).toEqual(all);
      expect(pages).toBe(Math.ceil(all.length / limit));
    }
    const first = await readHiveEventFeed({ after: undefined, limit: 2, now: NOW, store });
    expect(decodeCursor(first.nextCursor!)).toEqual({ t: first.data[1]!.occurredAt, id: first.data[1]!.id });
  });

  it("reads every row tied at a page boundary", async () => {
    const tied = memoryStore({
      activity: Array.from({ length: 6 }, (_, index) => ({
        id: `tie-${index}`,
        caseId: "case-c",
        kind: "case.reopened",
        detailJson: "{}",
        createdAt: at(15),
      })),
      approvals: [{ id: "approval-1", actionId: "action-1", createdAt: at(15) }],
    });
    const { events } = await readAll(2, tied);
    expect(new Set(events.map((event) => event.id)).size).toBe(7);
  });

  it("serves only the last 14 days", async () => {
    const edge = memoryStore({
      activity: [
        { id: "old", caseId: "case-a", kind: "case.reopened", detailJson: "{}", createdAt: at(14 * DAY + 1) },
        { id: "edge", caseId: "case-b", kind: "case.reopened", detailJson: "{}", createdAt: at(14 * DAY) },
        { id: "new", caseId: "case-c", kind: "case.reopened", detailJson: "{}", createdAt: at(14 * DAY - 1) },
      ],
    });
    const page = await readHiveEventFeed({ after: undefined, limit: 50, now: NOW, store: edge });
    expect(page.data.map((event) => event.sourceRef)).toEqual(["case-activity:edge", "case-activity:new"]);
    // A cursor older than the window starts from the window.
    const stale = encodeCursor({ t: at(30 * DAY).toISOString(), id: "cindertrace:case:x:opened" });
    const fromStale = await readHiveEventFeed({ after: stale, limit: 50, now: NOW, store: edge });
    expect(fromStale.data.map((event) => event.sourceRef)).toEqual(["case-activity:edge", "case-activity:new"]);
  });

  it("gives the same record the same ID every time", async () => {
    const one = await readAll(50);
    const two = await readAll(4);
    expect(two.events.map((event) => event.id)).toEqual(one.events.map((event) => event.id));
    expect(one.events.map((event) => event.id)).toContain("cindertrace:case:case-a:opened");
    expect(one.events.map((event) => event.id)).toContain("cindertrace:case:case-b:severity-raised:act-04");
    expect(new Set(one.events.map((event) => event.id)).size).toBe(one.events.length);
  });

  it("rejects a malformed cursor", async () => {
    for (const after of ["not*base64", encodeCursor({ id: "x" }), encodeCursor({ t: "yesterday", id: "x" }), "e30"])
      await expect(readHiveEventFeed({ after, limit: 5, now: NOW, store })).rejects.toMatchObject({ status: 400 });
  });

  it("drops an invalid event without logging its content", async () => {
    const bad = memoryStore({
      activity: [
        { id: "x".repeat(130), caseId: "case-a", kind: "case.reopened", detailJson: "{}", createdAt: at(3) },
        { id: "ok", caseId: "case-a", kind: "case.reopened", detailJson: "{}", createdAt: at(2) },
      ],
    });
    const dropped: unknown[] = [];
    const page = await readHiveEventFeed({ after: undefined, limit: 5, now: NOW, store: bad, onInvalid: (info) => dropped.push(info) });
    expect(page.data.map((event) => event.sourceRef)).toEqual(["case-activity:ok"]);
    expect(dropped).toEqual([{ type: "case.reopened", issues: 1 }]);
  });

  it("derives agent subjects only from valid, unambiguous identities", () => {
    expect(caseAgentSubject([])).toBeUndefined();
    expect(caseAgentSubject([{ caseId: "c", canonical: "agent-ref:node-x~ops", aliasesJson: '["magnus-node:node-x"]' }])).toEqual({
      agentRef: "node-x~ops",
      nodeId: "node-x",
    });
    expect(caseAgentSubject([{ caseId: "c", canonical: "actor:Bad.Actor", aliasesJson: '["magnus-node:Node.With.Dots"]' }])).toBeUndefined();
    expect(
      caseAgentSubject([{ caseId: "c", canonical: "actor:scout", aliasesJson: '["agent-ref:a1~p","agent-ref:a2~p"]' }]),
    ).toEqual({ actorId: "scout" });
  });
});
