/** Sign-in attempts allowed per window while RELAX_AUTH_LIMITS is on. */
export const RELAXED_AUTH_ATTEMPT_CEILING = 10_000;

/** Opt-in testing mode. Runtime only: it never changes stored configuration. */
export function authLimitsRelaxed(
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  return env["RELAX_AUTH_LIMITS"] === "true";
}

/** A typo must fail at startup rather than silently leave limits in either state. */
export function validateAuthLimitsConfig(
  env: NodeJS.ProcessEnv = process.env,
): void {
  const value = env["RELAX_AUTH_LIMITS"];
  if (value !== undefined && value !== "" && value !== "true" && value !== "false")
    throw new Error("RELAX_AUTH_LIMITS must be true or false");
}

export function relaxedAuthLimitsWarning(): string {
  const rule = "!".repeat(78);
  return [
    rule,
    "!! WARNING: AUTHENTICATION LIMITS ARE RELAXED (RELAX_AUTH_LIMITS=true)",
    `!! Sign-in throttles allow ${RELAXED_AUTH_ATTEMPT_CEILING} attempts per window, with no retry delay.`,
    "!! For testing only. Do not expose this instance to untrusted networks.",
    rule,
  ].join("\n");
}
