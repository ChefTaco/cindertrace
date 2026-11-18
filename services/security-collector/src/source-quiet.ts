import type { SecurityFusionSource } from "@cindertrace/contracts";

export interface QuietSourcePolicy {
  /** Hours without an event before a polled source reports `degraded`; 0 turns the signal off. */
  hours: number;
  sources: ReadonlySet<SecurityFusionSource>;
}

/**
 * `SECURITY_FUSION_QUIET_AFTER_HOURS` (default 6, 0 = off) and
 * `SECURITY_FUSION_QUIET_SOURCES` (comma separated, default `netflow`).
 * Only sources that always carry traffic belong here: an IDS or audit source
 * can be legitimately quiet for days.
 */
export function readQuietSourcePolicy(
  env: Record<string, string | undefined>,
  known: readonly SecurityFusionSource[],
): QuietSourcePolicy {
  const rawHours = env["SECURITY_FUSION_QUIET_AFTER_HOURS"]?.trim();
  const hours = rawHours ? Number(rawHours) : 6;
  if (!Number.isFinite(hours) || hours < 0 || hours > 24 * 30)
    throw new Error("SECURITY_FUSION_QUIET_AFTER_HOURS must be between 0 and 720");
  const names = (env["SECURITY_FUSION_QUIET_SOURCES"] ?? "netflow")
    .split(",")
    .map((name) => name.trim())
    .filter(Boolean);
  const unknown = names.filter((name) => !known.includes(name as SecurityFusionSource));
  if (unknown.length)
    throw new Error(`SECURITY_FUSION_QUIET_SOURCES names unknown sources: ${unknown.join(", ")}`);
  return { hours, sources: new Set(names as SecurityFusionSource[]) };
}

/**
 * The `degraded` message for a source whose polls succeed but that has had no
 * event for longer than the policy allows, or null. Without a last event the
 * collector's start time is the baseline, so a restart does not flag at once.
 */
export function quietSourceError(
  source: SecurityFusionSource,
  lastEventAt: string | undefined,
  startedAt: Date,
  now: Date,
  policy: QuietSourcePolicy,
): string | null {
  if (policy.hours === 0 || !policy.sources.has(source)) return null;
  const last = lastEventAt ? Date.parse(lastEventAt) : NaN;
  const baseline = Number.isFinite(last) ? Math.max(last, startedAt.getTime()) : startedAt.getTime();
  if (now.getTime() - baseline <= policy.hours * 3_600_000) return null;
  return lastEventAt
    ? `no events for more than ${policy.hours} hours (last event ${lastEventAt})`
    : `no events for more than ${policy.hours} hours since the collector started`;
}
