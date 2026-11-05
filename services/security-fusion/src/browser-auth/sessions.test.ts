import { expect, it, vi } from "vitest";
import { createHmac, randomUUID } from "node:crypto";
import { SignJWT } from "jose";
import { BrowserSessions, type SessionStore } from "./sessions.js";
const env = {
  SESSION_SECRET: "s".repeat(64),
  DASHBOARD_ADMIN_USERNAME: "admin",
  DASHBOARD_ADMIN_PASSWORD: "obviously-fake-password",
  SESSION_ISSUER: "fixture-console",
  SESSION_AUDIENCE: "fixture-console",
};
it("adopts exact legacy local session keys, credential generations and missing-role ADMIN defaults", async () => {
  const mget = vi.fn();
  const service = new BrowserSessions({ mget } as unknown as SessionStore, env);
  const sid = randomUUID();
  const digest = createHmac(
    "sha256",
    new TextEncoder().encode(env.SESSION_SECRET),
  )
    .update("admin")
    .digest("hex");
  expect(service.key("admin")).toBe("cindertrace_session:local:" + digest);
  const credentials = createHmac(
    "sha256",
    new TextEncoder().encode(env.SESSION_SECRET),
  )
    .update(JSON.stringify(["admin", "obviously-fake-password", ""]))
    .digest("hex");
  expect(service.credentialGeneration()).toBe(credentials);
  mget.mockResolvedValue([
    "legacy-generation",
    "legacy-generation:" + credentials,
  ]);
  const token = await new SignJWT({ username: "admin", sessionId: sid })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer(env.SESSION_ISSUER)
    .setAudience(env.SESSION_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(service.secret());
  expect((await service.verify(token))?.role).toBe("ADMIN");
  const adopted = new BrowserSessions({ mget } as unknown as SessionStore, {
    ...env,
    SESSION_ISSUER: " " + env.SESSION_ISSUER + " ",
    SESSION_AUDIENCE: " " + env.SESSION_AUDIENCE + " ",
  });
  expect((await adopted.verify(token))?.role).toBe("ADMIN");
  expect(mget).toHaveBeenLastCalledWith(
    service.key("admin") + ":generation",
    service.key("admin") + ":session:" + sid,
  );
  mget.mockResolvedValue([
    "new-generation",
    "legacy-generation:" + credentials,
  ]);
  expect(await service.verify(token)).toBeNull();
  mget.mockRejectedValue(Error("Redis offline"));
  await expect(service.verify(token)).rejects.toThrow();
});
it("rejects wrong issuer, wrong audience and legacy Hive OAuth cookies on the independent local path", async () => {
  const mget = vi.fn();
  const service = new BrowserSessions({ mget } as unknown as SessionStore, env);
  for (const [issuer, audience, provider] of [
    ["other", env.SESSION_AUDIENCE, undefined],
    [env.SESSION_ISSUER, "other", undefined],
    [env.SESSION_ISSUER, env.SESSION_AUDIENCE, "hive"],
  ]) {
    const token = await new SignJWT({
      username: "admin",
      sessionId: randomUUID(),
      ...(provider ? { provider } : {}),
    })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuer(issuer!)
      .setAudience(audience!)
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(service.secret());
    expect(await service.verify(token)).toBeNull();
  }
  expect(mget).not.toHaveBeenCalled();
});
