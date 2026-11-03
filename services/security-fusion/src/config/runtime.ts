/** Validate enabled capabilities without requiring any optional product. */
import { configuredCollectorCredentials } from "../services/security-fusion-ingest.js";
export function responseConfigured(
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  return Boolean(env["MAGNUS_RESPONSE_URL"] && env["MAGNUS_RESPONSE_SECRET"]);
}
export function validateRuntimeConfig(
  env: NodeJS.ProcessEnv = process.env,
): void {
  for (const name of [
    "DATABASE_URL",
    "REDIS_URL",
    "SECURITY_CONSOLE_TOKEN_SECRET",
    "AUDIT_HMAC_SECRET",
  ]) {
    if (!env[name] || (!name.endsWith("_URL") && env[name]!.length < 32))
      throw new Error(`${name} is required`);
  }
  if (env["SECURITY_CONSOLE_TOKEN_SECRET"] === env["AUDIT_HMAC_SECRET"])
    throw new Error("Console and audit secrets must be distinct");
  if (
    env["SECURITY_WRITES_ENABLED"] === "true" &&
    (!env["SECURITY_FUSION_RECEIPT_SIGNING_KEY"] ||
      env["SECURITY_FUSION_RECEIPT_SIGNING_KEY"].length < 32)
  )
    throw new Error(
      "Enabled security writes require a dedicated receipt signing key",
    );
  if (
    env["SECURITY_INGEST_ENABLED"] === "true" &&
    configuredCollectorCredentials(env).size === 0
  )
    throw new Error(
      "Enabled ingestion requires configured collector credentials",
    );
  if (
    Boolean(env["MAGNUS_RESPONSE_URL"]) !==
    Boolean(env["MAGNUS_RESPONSE_SECRET"])
  )
    throw new Error(
      "Magnus response URL and dedicated secret must be configured together",
    );
  if (
    env["MAGNUS_RESPONSE_URL"] &&
    (new URL(env["MAGNUS_RESPONSE_URL"]).protocol !== "https:" ||
      env["MAGNUS_RESPONSE_SECRET"]!.length < 32)
  )
    throw new Error("Magnus response requires HTTPS and a dedicated secret");
  if (
    env["MAGNUS_RESPONSE_SECRET"] &&
    [
      "SESSION_SECRET",
      "SECURITY_CONSOLE_TOKEN_SECRET",
      "AUDIT_HMAC_SECRET",
      "SECURITY_FUSION_RECEIPT_SIGNING_KEY",
    ].some((name) => env[name] === env["MAGNUS_RESPONSE_SECRET"])
  )
    throw new Error(
      "Magnus response requires a distinct purpose-specific secret",
    );
  if (env["SECURITY_DISPATCH_ENABLED"] === "true" && !responseConfigured(env))
    throw new Error("Dispatch requires the Magnus response bridge");
  if (
    env["MAGNUS_INVENTORY_URL"] &&
    (!env["MAGNUS_INVENTORY_TOKEN"] ||
      new URL(env["MAGNUS_INVENTORY_URL"]).protocol !== "https:")
  )
    throw new Error("Magnus inventory requires HTTPS and its scoped token");
}
