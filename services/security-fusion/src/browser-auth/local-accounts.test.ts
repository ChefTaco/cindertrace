import { beforeAll, expect, it, vi } from "vitest";
import { Hono } from "hono";
import { decodeJwt } from "jose";
import { authenticateLocal, localAccounts } from "./credentials.js";
import { BrowserSessions, type SessionStore } from "./sessions.js";
import { browserAuthRouter } from "./routes.js";
import { totpCode } from "./totp.js";

// A synthetic 160-bit base32 key: 32 "A"s decode to 20 zero bytes.
const TOTP_KEY = "A".repeat(32);
let env: Record<string, string>;
// Session tests need no verifiable hash: the binding only digests the configured value.
const sessionEnv = {
  CINDERTRACE_BROWSER_AUTH_ENABLED: "true",
  CINDERTRACE_ADMIN_USERNAME: "admin",
  CINDERTRACE_ADMIN_PASSWORD_HASH: "$argon2id$v=19$m=65536,t=3,p=4$fixture$admin",
  SESSION_SECRET: "s".repeat(64),
  CINDERTRACE_LOCAL_ACCOUNTS_JSON: JSON.stringify([
    { username: "viewer", passwordHash: "$argon2id$v=19$m=65536,t=3,p=4$fixture$viewer", role: "VIEWER", userId: "reviewed-viewer" },
  ]),
};
beforeAll(async () => {
  // Argon2id of "analyst-fixture-password" and "viewer-fixture-password", made once offline.
  const analyst = "$argon2id$v=19$m=65536,p=4,t=3$TjbFmFNbLo1OSnh67JrHFQ$fFPXUu19EJQoFtj5QqV+QUNatw0SbljVZstEM0RhsM4";
  const viewer = "$argon2id$v=19$m=65536,p=4,t=3$hl6AYvYMpIfkppIMs+pjdQ$TMgPEeHxn8fukYmcNZvt2ampmwjavWSNlwNDsztzyPg";
  env = {
    CINDERTRACE_BROWSER_AUTH_ENABLED: "true",
    CINDERTRACE_PUBLIC_ORIGIN: "https://ui.example.com",
    CINDERTRACE_ADMIN_USERNAME: "admin",
    CINDERTRACE_ADMIN_PASSWORD: "admin-fixture-password",
    SESSION_SECRET: "s".repeat(64),
    CINDERTRACE_LOCAL_ACCOUNTS_JSON: JSON.stringify([
      { username: "analyst", passwordHash: analyst, role: "OPERATOR", totpSecret: TOTP_KEY },
      { username: "viewer", passwordHash: viewer, role: "VIEWER", userId: "reviewed-viewer" },
    ]),
  };
});

it("lists the administrator and the configured accounts, and refuses bad account settings", () => {
  expect(localAccounts(env).map((a) => [a.username, a.role, a.userId, a.administrator, Boolean(a.totpSecret)])).toEqual([
    ["admin", "ADMIN", "admin", true, false],
    ["analyst", "OPERATOR", "local:analyst", false, true],
    ["viewer", "VIEWER", "reviewed-viewer", false, false],
  ]);
  const one = (account: Record<string, unknown>) => ({ ...env, CINDERTRACE_LOCAL_ACCOUNTS_JSON: JSON.stringify([account]) });
  const base = { username: "x", passwordHash: "$argon2id$v=19$fixture", role: "OPERATOR" };
  for (const bad of [
    { ...env, CINDERTRACE_LOCAL_ACCOUNTS_JSON: "[{" },
    one({ ...base, role: "OWNER" }),
    one({ ...base, passwordHash: "plaintext" }),
    one({ ...base, username: "admin" }),
    one({ ...base, userId: "admin" }),
    one({ ...base, totpSecret: "MZXW6===" }),
    one({ ...base, totpSecret: "not base32!" }),
    one({ ...base, extra: true }),
  ])
    expect(() => localAccounts(bad)).toThrow();
  const encoded = { ...env, CINDERTRACE_LOCAL_ACCOUNTS_JSON_B64: Buffer.from(JSON.stringify([base])).toString("base64") };
  expect(localAccounts(encoded).map((a) => a.username)).toEqual(["admin", "x"]);
});

it("authenticates each account with its own password only", async () => {
  expect((await authenticateLocal("analyst", "analyst-fixture-password", env))?.role).toBe("OPERATOR");
  expect(await authenticateLocal("analyst", "viewer-fixture-password", env)).toBeNull();
  expect(await authenticateLocal("nobody", "analyst-fixture-password", env)).toBeNull();
  expect((await authenticateLocal("admin", "admin-fixture-password", env))?.administrator).toBe(true);
});

function memoryStore() {
  const data = new Map<string, string>();
  return {
    data,
    store: {
      eval: vi.fn(async (script: string, _n: number, ...args: string[]) => {
        if (script.includes("tonumber(ARGV[1]) <= last")) {
          const last = Number(data.get(args[0]!) ?? -1);
          if (Number(args[1]) <= last) return 0;
          data.set(args[0]!, args[1]!);
          return 1;
        }
        // Session creation: record generation and session as the CREATE script does.
        const generation = data.get(args[0]!) ?? args[3]!;
        data.set(args[0]!, generation);
        data.set(args[2]!, generation + ":" + args[5]);
        return generation;
      }),
      mget: vi.fn(async (...keys: string[]) => keys.map((key) => data.get(key) ?? null)),
      set: vi.fn(async (key: string, value: string) => void data.set(key, value)),
      del: vi.fn(async (key: string) => void data.delete(key)),
    } as unknown as SessionStore,
  };
}

it("issues sessions with the account's role, reads the role live, and revokes on a role change", async () => {
  const memory = memoryStore();
  const service = new BrowserSessions(memory.store, sessionEnv);
  const token = await service.create("viewer");
  expect(decodeJwt(token)).toMatchObject({ role: "VIEWER", userId: "reviewed-viewer" });
  expect(await service.verify(token)).toMatchObject({ role: "VIEWER", userId: "reviewed-viewer" });
  const promoted = JSON.parse(sessionEnv.CINDERTRACE_LOCAL_ACCOUNTS_JSON).map((a: { username: string }) =>
    a.username === "viewer" ? { ...a, role: "OPERATOR" } : a);
  const changed = new BrowserSessions(memory.store, { ...sessionEnv, CINDERTRACE_LOCAL_ACCOUNTS_JSON: JSON.stringify(promoted) });
  // A role change is part of the session binding: existing sessions end.
  expect(await changed.verify(token)).toBeNull();
  const removed = new BrowserSessions(memory.store, { ...sessionEnv, CINDERTRACE_LOCAL_ACCOUNTS_JSON: "[]" });
  expect(await removed.verify(token)).toBeNull();
  // The administrator keeps the original binding, so sessions from before survive an upgrade.
  const adminOnly = new BrowserSessions(memory.store, { ...sessionEnv, CINDERTRACE_LOCAL_ACCOUNTS_JSON: "[]" });
  expect(service.credentialGeneration("admin")).toBe(adminOnly.credentialGeneration());
});

it("signs in an account with TOTP only with a fresh code, once", async () => {
  // The session service is a stub here; its TOTP step rule mirrors the Redis script.
  const used = new Map<string, number>();
  const service = {
    create: vi.fn(async () => "fixture-session"),
    consumeTotpStep: vi.fn(async (username: string, step: number) => {
      if (step <= (used.get(username) ?? -1)) return false;
      used.set(username, step);
      return true;
    }),
  } as unknown as BrowserSessions;
  const audit = vi.fn().mockResolvedValue(undefined);
  const app = new Hono().route("/auth", browserAuthRouter({
    env,
    sessions: async () => service,
    admission: vi.fn().mockResolvedValue({
      allowed: true, retryAfterSeconds: 0, sourceLabel: "s", usernameLabel: "u", pairLabel: "p",
      release: vi.fn().mockResolvedValue(undefined), clearSuccessfulPair: vi.fn().mockResolvedValue(undefined),
    }),
    audit,
  }));
  const login = (body: Record<string, string>) => app.request("/auth/login", {
    method: "POST",
    headers: { Origin: "https://ui.example.com", "Content-Type": "application/json" },
    body: JSON.stringify({ username: "analyst", password: "analyst-fixture-password", ...body }),
  });
  const missing = await login({});
  expect(missing.status).toBe(401);
  expect(await missing.json()).toEqual({ error: "Authentication code required", totpRequired: true });
  const code = totpCode(Buffer.alloc(20), Math.floor(Date.now() / 30_000));
  expect((await login({ totp: code === "000000" ? "111111" : "000000" })).status).toBe(401);
  const ok = await login({ totp: code });
  expect(ok.status).toBe(200);
  expect(await ok.json()).toMatchObject({ username: "analyst", role: "OPERATOR", userId: "local:analyst" });
  // The same code cannot be used twice.
  expect((await login({ totp: code })).status).toBe(401);
  expect(audit.mock.calls.map((call) => [call[0], call[2].reason])).toEqual([
    ["auth.login_failed", "totp_required"],
    ["auth.login_failed", "totp_invalid"],
    ["auth.login_succeeded", undefined],
    ["auth.login_failed", "totp_invalid"],
  ]);
});
