const values = new Map<string, number>();
export function incMetric(name: string, amount = 1): void {
  values.set(name, (values.get(name) ?? 0) + amount);
}
export function setMetricGauge(name: string, value: number): void {
  values.set(name, value);
}
export function renderMetrics(): string {
  return (
    [...values]
      .map(
        ([k, v]) =>
          `security_fusion_${k.replace(/[A-Z]/g, (x) => "_" + x.toLowerCase())} ${v}`,
      )
      .join("\n") + "\n"
  );
}

/**
 * The backup alert threshold: with CINDERTRACE_BACKUP_MAX_AGE_HOURS set, /metrics reports it
 * as `security_fusion_backup_max_age_seconds` and `security_fusion_backup_stale` (1 when the
 * last successful backup is older than that, or there is none). Unset, neither is reported.
 */
export function backupStaleness(
  lastSuccessMs: number,
  env: NodeJS.ProcessEnv = process.env,
  now = Date.now(),
): string {
  const raw = env["CINDERTRACE_BACKUP_MAX_AGE_HOURS"];
  if (!raw || !/^\d+$/.test(raw) || Number(raw) < 1) return "";
  const max = Number(raw) * 3600;
  const stale = !Number.isFinite(lastSuccessMs) || lastSuccessMs <= 0 || (now - lastSuccessMs) / 1000 > max;
  return `\nsecurity_fusion_backup_max_age_seconds ${max}\nsecurity_fusion_backup_stale ${stale ? 1 : 0}`;
}
