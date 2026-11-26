import { HttpError } from "../middleware/error-handler.js";
import type { AuthTokenPayload } from "../types/index.js";

/**
 * Optional safeguards for approving a response action (both off unless configured):
 * - SECURITY_APPROVAL_MAX_AUTH_AGE_SECONDS (60 to 86400): the approver must have signed in
 *   within this many seconds; an older session gets 401 REAUTHENTICATION_REQUIRED.
 * - SECURITY_APPROVAL_DISTINCT_APPROVER=true: whoever previewed or requested an action
 *   cannot approve it (403 DISTINCT_APPROVER_REQUIRED). Rejecting stays open to them.
 */
export interface ApprovalPolicy {
  maxAuthAgeSeconds?: number;
  distinctApprover: boolean;
}

export function approvalPolicy(env: NodeJS.ProcessEnv = process.env): ApprovalPolicy {
  const age = env["SECURITY_APPROVAL_MAX_AUTH_AGE_SECONDS"]?.trim();
  const distinct = env["SECURITY_APPROVAL_DISTINCT_APPROVER"]?.trim();
  if (distinct && !["true", "false"].includes(distinct))
    throw new Error("SECURITY_APPROVAL_DISTINCT_APPROVER must be true or false");
  if (age && (!/^\d+$/.test(age) || Number(age) < 60 || Number(age) > 86_400))
    throw new Error("SECURITY_APPROVAL_MAX_AUTH_AGE_SECONDS must be a whole number from 60 to 86400");
  return { ...(age ? { maxAuthAgeSeconds: Number(age) } : {}), distinctApprover: distinct === "true" };
}

/** Step-up for approval: refuse a sign-in older than the configured age, or of unknown age. */
export function requireRecentAuthentication(
  user: AuthTokenPayload,
  policy: ApprovalPolicy = approvalPolicy(),
  now = Date.now(),
): void {
  if (policy.maxAuthAgeSeconds === undefined) return;
  if (user.authenticatedAt === undefined || now - user.authenticatedAt > policy.maxAuthAgeSeconds * 1000)
    throw new HttpError(401, "REAUTHENTICATION_REQUIRED", "Sign in again to approve response actions");
}

/** Two-person rule: the approver is neither the person who previewed nor who requested the action. */
export function requireDistinctApprover(
  actorId: string,
  requesters: Array<string | null | undefined>,
  policy: ApprovalPolicy = approvalPolicy(),
): void {
  if (policy.distinctApprover && requesters.includes(actorId))
    throw new HttpError(403, "DISTINCT_APPROVER_REQUIRED", "Another administrator must approve this action");
}
