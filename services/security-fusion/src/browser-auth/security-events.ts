import { createHmac, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { open, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { isIP } from "node:net";
/** Preserve the console collector's immutable event format after API adoption. */
export function browserSecurityEvent(
  event: string,
  address: string,
  username: string,
  env: NodeJS.ProcessEnv = process.env,
) {
  const key = env.AUTH_RATE_LIMIT_LABEL_KEY ?? env.SESSION_SECRET;
  if (!key || key.length < 32)
    throw Error("Authentication audit identity secret unavailable");
  const normalized = address.replace(/^::ffff:/, "");
  const source = isIP(normalized) ? normalized : "unverified",
    account = username.trim().toLowerCase().slice(0, 512);
  const label = (kind: string, value: string) =>
    createHmac("sha256", key)
      .update(`${kind}\0${value}`)
      .digest("hex")
      .slice(0, 24);
  return {
    schemaVersion: 1,
    eventId: randomUUID(),
    occurredAt: new Date().toISOString(),
    application: "cindertrace_ui",
    event,
    method: "local",
    sourceAddress: source,
    accountLabel: label("account", account),
    sourceLabel: label("source", source),
    pairLabel: label("pair", `local\0${source}\0${account}`),
  };
}
export async function appendBrowserSecurityEvent(
  event: string,
  address: string,
  username: string,
  env: NodeJS.ProcessEnv = process.env,
): Promise<void> {
  const record = browserSecurityEvent(event, address, username, env);
  const destination =
    env.UI_SECURITY_LOG_PATH ??
    join(env.CINDERTRACE_STATE_DIR ?? "/data", "ui-security", "events.jsonl");
  await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
  const file = await open(
    destination,
    constants.O_WRONLY |
      constants.O_APPEND |
      constants.O_CREAT |
      constants.O_NOFOLLOW,
    0o640,
  );
  try {
    await file.chmod(0o640);
    await file.writeFile(JSON.stringify(record) + "\n");
    await file.datasync();
  } finally {
    await file.close();
  }
}
