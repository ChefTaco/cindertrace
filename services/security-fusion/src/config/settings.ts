/**
 * Setting names that changed when the standalone console was retired. The new
 * `CINDERTRACE_*` name wins; the old `DASHBOARD_*` name keeps working (Hive suite
 * installations and existing `.env` files use it). Setting both to different values is
 * refused at startup.
 */
export const settingAliases = {
  CINDERTRACE_PUBLIC_ORIGIN: "DASHBOARD_PUBLIC_ORIGIN",
  CINDERTRACE_ADMIN_USERNAME: "DASHBOARD_ADMIN_USERNAME",
  CINDERTRACE_ADMIN_USERNAME_B64: "DASHBOARD_ADMIN_USERNAME_B64",
  CINDERTRACE_ADMIN_PASSWORD: "DASHBOARD_ADMIN_PASSWORD",
  CINDERTRACE_ADMIN_PASSWORD_B64: "DASHBOARD_ADMIN_PASSWORD_B64",
  CINDERTRACE_ADMIN_PASSWORD_HASH: "DASHBOARD_ADMIN_PASSWORD_HASH",
  CINDERTRACE_ADMIN_PASSWORD_HASH_B64: "DASHBOARD_ADMIN_PASSWORD_HASH_B64",
  CINDERTRACE_ADMIN_ACCOUNT_ID: "DASHBOARD_ADMIN_ACCOUNT_ID",
} as const;
export type AliasedSetting = keyof typeof settingAliases;

/** The value of a renamed setting: the new name, else its legacy name. */
export function setting(
  env: NodeJS.ProcessEnv,
  name: AliasedSetting,
): string | undefined {
  return env[name] ?? env[settingAliases[name]];
}

/** Refuse configurations that set a setting under both names with different values. */
export function validateSettingAliases(env: NodeJS.ProcessEnv): void {
  for (const [name, legacy] of Object.entries(settingAliases))
    if (env[name] !== undefined && env[legacy] !== undefined && env[name] !== env[legacy])
      throw new Error(`${name} and its legacy name ${legacy} disagree; keep one`);
}

/**
 * `SECURITY_APPROVAL_MODE`: `local` (approval by a Cindertrace administrator; `console`
 * is its legacy spelling) or `external` (the signed external approval channel). The
 * case detail keeps reporting `console` for local approval: that is HiveXUI's wire value.
 */
export function approvalMode(env: NodeJS.ProcessEnv = process.env): "local" | "external" {
  return env["SECURITY_APPROVAL_MODE"] === "external" ? "external" : "local";
}
