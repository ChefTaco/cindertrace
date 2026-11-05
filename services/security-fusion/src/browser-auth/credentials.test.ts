import { expect, it } from "vitest";
import { hash, argon2id } from "argon2";
import { credentials, validateLocalCredentials } from "./credentials.js";
import { prepareBrowserCredentials } from "./hash-password.js";
import {
  mkdtemp,
  writeFile,
  readFile,
  chmod,
  symlink,
  rm,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
it("uses only dedicated credentials, preserves encoded precedence and validates Argon2id without username shortcuts", async () => {
  const password = "obviously-fake-password";
  const encoded = await hash(password, { type: argon2id });
  const env = {
    DASHBOARD_ADMIN_USERNAME: "admin",
    DASHBOARD_ADMIN_PASSWORD_HASH: encoded,
  };
  expect(await validateLocalCredentials("admin", password, env)).toBe(true);
  expect(await validateLocalCredentials("other", password, env)).toBe(false);
  expect(await validateLocalCredentials("admin", "wrong", env)).toBe(false);
  expect(
    credentials({
      ...env,
      DASHBOARD_ADMIN_USERNAME_B64:
        Buffer.from("encoded-admin").toString("base64"),
    }).username,
  ).toBe("encoded-admin");
  expect(() =>
    credentials({ SWARM_PASSWORD: password, DEPLOY_PASSWORD: password }),
  ).toThrow(/Dedicated/);
  expect(() =>
    credentials({ ...env, DASHBOARD_ADMIN_USERNAME_B64: "%%%" }),
  ).toThrow(/encoded/);
});
it("prepares one protected stable hash, refuses changed input and unsafe files without replacing credentials", async () => {
  const directory = await mkdtemp(join(tmpdir(), "cinder-auth-fixture-"));
  const config = join(directory, "input.json"),
    output = join(directory, "result.json");
  try {
    await writeFile(
      config,
      JSON.stringify({
        username: "admin",
        password: "obviously-fake-password",
      }),
      { mode: 0o600 },
    );
    await prepareBrowserCredentials(config, output);
    const first = await readFile(output, "utf8");
    await prepareBrowserCredentials(config, output);
    expect(await readFile(output, "utf8")).toBe(first);
    await writeFile(
      config,
      JSON.stringify({
        username: "admin",
        password: "different-fake-password",
      }),
    );
    await expect(prepareBrowserCredentials(config, output)).rejects.toThrow();
    expect(await readFile(output, "utf8")).toBe(first);
    await chmod(config, 0o644);
    await expect(prepareBrowserCredentials(config, output)).rejects.toThrow();
    await chmod(config, 0o600);
    await symlink(config, join(directory, "link.json"));
    await expect(
      prepareBrowserCredentials(join(directory, "link.json"), output),
    ).rejects.toThrow();
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
