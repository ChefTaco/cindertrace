import { decodeCursor, encodeCursor } from "@hivemagnus/hive-common/events";
import { HttpError } from "../middleware/error-handler.js";

/**
 * Keyset pagination for the newest-first lists HiveXUI pages through. A cursor names the
 * last row served, by its sort value and ID, so a page never repeats or skips a row while
 * new ones arrive. Pass `?cursor=<nextCursor>`; `nextCursor` is null on the last page.
 */
export type Position = { at: Date | number; id: string };

export function readPosition(cursor: string | undefined, kind: "time" | "sequence"): Position | undefined {
  if (cursor === undefined || cursor === "") return undefined;
  let value: Record<string, string | number>;
  try {
    value = decodeCursor(cursor);
  } catch {
    throw new HttpError(400, "INVALID_CURSOR", "The cursor is not valid");
  }
  const id = value["id"];
  const raw = value["at"];
  const at =
    kind === "time"
      ? typeof raw === "string" ? new Date(raw) : new Date(Number.NaN)
      : typeof raw === "number" && Number.isSafeInteger(raw) ? raw : Number.NaN;
  if (typeof id !== "string" || !id || id.length > 128 || Number.isNaN(Number(at)))
    throw new HttpError(400, "INVALID_CURSOR", "The cursor is not valid");
  return { at, id };
}

/** The Prisma condition for rows strictly after `position` in (field desc, id desc) order. */
export function after(field: string, position: Position | undefined): Record<string, unknown> {
  if (!position) return {};
  return {
    OR: [
      { [field]: { lt: position.at } },
      { [field]: position.at, id: { lt: position.id } },
    ],
  };
}

export function newestFirst(field: string): Array<Record<string, "desc">> {
  return [{ [field]: "desc" }, { id: "desc" }];
}

/** Trim the extra row fetched to detect a further page and name the cursor for it. */
export function page<T extends { id: string }>(
  rows: T[],
  limit: number,
  at: (row: T) => Date | number,
): { rows: T[]; nextCursor: string | null } {
  if (rows.length <= limit) return { rows, nextCursor: null };
  const kept = rows.slice(0, limit), last = kept.at(-1)!, value = at(last);
  return {
    rows: kept,
    nextCursor: encodeCursor({ at: value instanceof Date ? value.toISOString() : value, id: last.id }),
  };
}
