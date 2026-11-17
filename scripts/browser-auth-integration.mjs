import assert from "node:assert/strict";
import { createHmac, randomBytes, randomUUID } from "node:crypto";
import { Redis } from "ioredis";
import { SignJWT, jwtVerify } from "jose";
import { BrowserSessions } from "../services/security-fusion/dist/browser-auth/sessions.js";
import { createAuthProtection } from "../services/security-fusion/dist/browser-auth/throttling.js";
if (
  process.env.CINDERTRACE_AUTH_TEST_CONFIRM !==
    "isolated-synthetic-installation" ||
  !process.env.CINDERTRACE_TEST_REDIS_URL
)
  throw Error("Explicit disposable Redis authentication fixture required");
const env = {
  SESSION_SECRET: randomBytes(48).toString("hex"),
  DASHBOARD_ADMIN_USERNAME: "admin",
  DASHBOARD_ADMIN_PASSWORD: "synthetic-" + randomBytes(24).toString("hex"),
  REDIS_URL: process.env.CINDERTRACE_TEST_REDIS_URL,
  REDIS_PREFIX: "cindertrace-auth-test-" + randomUUID() + ":",
  SESSION_ISSUER: "cindertrace-test-console",
  SESSION_AUDIENCE: "cindertrace-test-console",
};
const client = new Redis(env.REDIS_URL, {
  maxRetriesPerRequest: 1,
  connectTimeout: 2000,
  commandTimeout: 2500,
});
client.on("error", () => undefined);
const sessions = new BrowserSessions(client, env);
// A session record exactly as Cindertrace 0.7.x's standalone console wrote it (Redis keys,
// generation and credential digest), so the API keeps accepting and revoking existing cookies.
const recordKey = username => `cindertrace_session:local:${createHmac("sha256", sessions.secret()).update(username).digest("hex")}`;
// The credential digest is the API's own (credentials.test.ts covers its inputs).
const credentialDigest = () => sessions.credentialGeneration();
async function legacySession(username) {
  const id = randomUUID(), key = recordKey(username), generation = randomUUID();
  await client.set(`${key}:generation`, generation, "EX", 86400);
  await client.zadd(`${key}:sessions`, Date.now() * 1000 + 86400e6, id);
  await client.set(`${key}:session:${id}`, `${generation}:${credentialDigest()}`, "EX", 86400);
  return id;
}
async function legacyValid(username, id) {
  const key = recordKey(username);
  const [generation, record] = await client.mget(`${key}:generation`, `${key}:session:${id}`);
  return Boolean(generation && record === `${generation}:${credentialDigest()}`);
}
try {
  await client.ping();
  const legacyId = await legacySession("admin");
  const legacyToken = await new SignJWT({
    username: "admin",
    sessionId: legacyId,
  })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer(env.SESSION_ISSUER)
    .setAudience(env.SESSION_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(sessions.secret());
  assert.equal((await sessions.verify(legacyToken))?.sessionId, legacyId);
  const apiToken = await sessions.create("admin"),
    payload = (await jwtVerify(apiToken, sessions.secret())).payload;
  assert.equal(await legacyValid(payload.username, payload.sessionId), true);
  await sessions.revoke(await sessions.verify(legacyToken));
  assert.equal(await legacyValid("admin", legacyId), false);
  for (let index = 0; index < 55; index++) await sessions.create("admin");
  assert.equal(await client.zcard(sessions.key("admin") + ":sessions"), 50);
  const current = await sessions.create("admin");
  const signed = await sessions.verify(current);
  assert(signed);
  await sessions.revoke(signed, true);
  assert.equal(await sessions.verify(current), null);
  Object.assign(process.env, env);
  const begin = createAuthProtection(client, async () => {});
  for (let index = 0; index < 6; index++) {
    const permit = await begin("198.51.100.1", "admin");
    assert.equal(permit.allowed, index < 5);
    await permit.release();
  }
  process.stdout.write(
    JSON.stringify({
      ok: true,
      checks: [
        "legacy session adopted without reseeding",
        "API session uses the 0.7.x record format",
        "single-session and all-session revocation",
        "exact fifty-session bound",
        "durable pair throttling",
      ],
      nativeIssuer: env.SESSION_ISSUER,
    }) + "\n",
  );
} finally {
  for (const pattern of [sessions.key("admin") + "*", env.REDIS_PREFIX + "*"]) {
    let cursor = "0";
    do {
      const result = await client.scan(cursor, "MATCH", pattern, "COUNT", 100);
      cursor = result[0];
      if (result[1].length) await client.del(...result[1]);
    } while (cursor !== "0");
  }
  await client.quit();
}
