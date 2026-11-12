import { Hono } from "hono";
import { parseFeedQuery } from "@hivemagnus/hive-common/events";
import type { AppVariables } from "../types/index.js";
import { authMiddleware, requirePermission } from "../middleware/auth.js";
import { HttpError } from "../middleware/error-handler.js";
import { readHiveEventFeed } from "../services/hive-events.js";

/** Suite routes mounted at `/api/v1/hive`. The event feed uses the same auth and role rules as case reads. */
export const hiveEventsRouter = new Hono<AppVariables>();

hiveEventsRouter.use("*", authMiddleware);
hiveEventsRouter.use("*", requirePermission("security-fusion:read"));

hiveEventsRouter.get("/events", async (c) => {
  let query;
  try {
    query = parseFeedQuery(c.req.queries());
  } catch (error) {
    throw new HttpError(400, "INVALID_QUERY", error instanceof Error ? error.message : "Invalid feed query");
  }
  return c.json(await readHiveEventFeed(query));
});
