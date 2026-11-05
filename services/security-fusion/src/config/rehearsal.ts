export const REHEARSAL_DISABLED_FLAGS = [
  "SECURITY_DISPATCH_ENABLED",
  "SECURITY_RETENTION_ENABLED",
  "SECURITY_INGEST_ENABLED",
  "SECURITY_WRITES_ENABLED",
  "SECURITY_NOTIFICATIONS_ENABLED",
  "SECURITY_FUSION_UDP_ENABLED",
  "TAILSCALE_LOCAL_ENABLED",
] as const;
export function isRehearsal(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.HIVE_REHEARSAL === "true";
}
export function applyRehearsalGuards(env: NodeJS.ProcessEnv): void {
  if (
    env.HIVE_REHEARSAL !== undefined &&
    !["true", "false"].includes(env.HIVE_REHEARSAL)
  )
    throw Error("HIVE_REHEARSAL must be true or false");
  if (isRehearsal(env))
    for (const name of REHEARSAL_DISABLED_FLAGS) env[name] = "false";
}
export function securityWritesEnabled(
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  return !isRehearsal(env) && env.SECURITY_WRITES_ENABLED === "true";
}
