import { decodeCursor, encodeCursor } from "@hivemagnus/hive-common/events";
import { auditDetails, validateHiveAuditRecord } from "@hivemagnus/hive-common/audit";
import type { CindertraceAuditRecord } from "@cindertrace/contracts";
import { HttpError } from "../middleware/error-handler.js";
import { auditDayEntries, listAuditDays, type AuditLogEntry } from "./audit-service.js";

/**
 * Cindertrace's own audit as HiveAuditRecord v1, oldest first, the format the suite's
 * products export at `/audit/export`. The source stays the hash-chained daily JSONL files;
 * a cursor names a day and a line, so a page resumes exactly after the last record served.
 * Client addresses are not exported.
 */
const FAILURES = /\.(login_failed|login_throttled|login_rejected|login_error|oauth_rejected)$|_failed$|\.fail(ed|ure)$/;
const MAX_DETAILS_BYTES = 4096;

function actor(entry: AuditLogEntry): CindertraceAuditRecord["actor"] {
  const id = (entry.actorId || "unknown").slice(0, 512);
  if (id.startsWith("service:")) return { type: "service", id };
  if (id.startsWith("system:") || entry.actorType === "system") return { type: "system", id };
  if (entry.actorType === "agent") return { type: "agent", id };
  return { type: "user", id };
}

function details(entry: AuditLogEntry): Record<string, string | number | boolean | null> {
  // Flat, redacted and bounded the suite's way (hive-common /audit), plus the chain state.
  return { ...auditDetails(entry.details ?? {}, { maxBytes: MAX_DETAILS_BYTES - 64 }), chain: entry.verificationState ?? "invalid" };
}

export function auditRecord(entry: AuditLogEntry): CindertraceAuditRecord {
  return {
    id: `cindertrace:audit:${entry.id}`,
    product: "cindertrace",
    occurredAt: entry.timestamp,
    action: entry.action,
    outcome: FAILURES.test(entry.action) ? "failure" : "success",
    actor: actor(entry),
    ...(entry.targetType || entry.targetId
      ? { target: { ...(entry.targetType ? { type: entry.targetType.slice(0, 160) } : {}), ...(entry.targetId ? { id: entry.targetId.slice(0, 512) } : {}) } }
      : {}),
    details: details(entry),
  };
}

function position(cursor: string | undefined): { day: string; index: number } | undefined {
  if (!cursor) return undefined;
  let value: Record<string, string | number>;
  try {
    value = decodeCursor(cursor);
  } catch {
    throw new HttpError(400, "INVALID_CURSOR", "The cursor is not valid");
  }
  if (typeof value["d"] !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value["d"]) || !Number.isSafeInteger(value["n"]) || Number(value["n"]) < 0)
    throw new HttpError(400, "INVALID_CURSOR", "The cursor is not valid");
  return { day: value["d"], index: Number(value["n"]) };
}

/**
 * One page: up to `limit` records after `after`. As in the suite's export contract,
 * nextCursor names the last entry read (also on a final page, and past skipped entries);
 * null only when nothing was read, that is caught up.
 */
export async function exportAuditRecords(options: { after?: string | undefined; limit: number }): Promise<{
  data: CindertraceAuditRecord[];
  nextCursor: string | null;
}> {
  const start = position(options.after);
  const days = (await listAuditDays())
    .filter((day) => /^\d{4}-\d{2}-\d{2}$/.test(day) && (!start || day >= start.day))
    .sort();
  const data: CindertraceAuditRecord[] = [];
  let last: { day: string; index: number } | undefined;
  for (const day of days) {
    for await (const { index, entry } of auditDayEntries(day)) {
      if (start && day === start.day && index <= start.index) continue;
      last = { day, index };
      // An entry that does not form a valid record is skipped; the cursor still moves past it.
      if (!/^[a-z0-9_-]+(\.[a-z0-9_-]+)*$/.test(entry.action) || !/^[A-Za-z0-9._:-]{1,200}$/.test(entry.id)) continue;
      const record = auditRecord(entry);
      if (!validateHiveAuditRecord(record, { strict: true }).ok) continue;
      data.push(record);
      if (data.length >= options.limit) break;
    }
    if (data.length >= options.limit) break;
  }
  return { data, nextCursor: last ? encodeCursor({ d: last.day, n: last.index }) : null };
}
