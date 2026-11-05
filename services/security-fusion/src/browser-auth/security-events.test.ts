import { expect, it } from "vitest";
import { createHmac } from "node:crypto";
import {
  browserSecurityEvent,
  appendBrowserSecurityEvent,
} from "./security-events.js";
import { mkdtemp, readFile, symlink, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
it("preserves legacy collector event fields and pseudonyms without submitted account or credential values", () => {
  const env = { SESSION_SECRET: "s".repeat(64) };
  const event = browserSecurityEvent(
    "auth.login_failed",
    "::ffff:198.51.100.1",
    "Synthetic-User",
    env,
  );
  expect(event).toMatchObject({
    schemaVersion: 1,
    application: "cindertrace_ui",
    event: "auth.login_failed",
    method: "local",
    sourceAddress: "198.51.100.1",
  });
  expect(event.accountLabel).toBe(
    createHmac("sha256", env.SESSION_SECRET)
      .update("account\0synthetic-user")
      .digest("hex")
      .slice(0, 24),
  );
  expect(event.pairLabel).toBe(
    createHmac("sha256", env.SESSION_SECRET)
      .update(["pair", "local", "198.51.100.1", "synthetic-user"].join("\0"))
      .digest("hex")
      .slice(0, 24),
  );
  expect(JSON.stringify(event)).not.toContain("Synthetic-User");
});
it("appends compatible records without replacing history and refuses a linked audit destination", async () => {
  const directory = await mkdtemp(join(tmpdir(), "cinder-audit-fixture-"));
  const path = join(directory, "events.jsonl");
  const env = { SESSION_SECRET: "s".repeat(64), UI_SECURITY_LOG_PATH: path };
  try {
    await appendBrowserSecurityEvent(
      "auth.login_failed",
      "198.51.100.1",
      "synthetic-user",
      env,
    );
    const first = await readFile(path, "utf8");
    await appendBrowserSecurityEvent(
      "auth.login_succeeded",
      "198.51.100.1",
      "synthetic-user",
      env,
    );
    expect((await readFile(path, "utf8")).startsWith(first)).toBe(true);
    await symlink(path, join(directory, "link.jsonl"));
    await expect(
      appendBrowserSecurityEvent(
        "auth.logout",
        "198.51.100.1",
        "synthetic-user",
        { ...env, UI_SECURITY_LOG_PATH: join(directory, "link.jsonl") },
      ),
    ).rejects.toThrow();
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
