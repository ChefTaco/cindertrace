import { timingSafeEqual } from "node:crypto";
import { verify } from "argon2";

/** Preserve dedicated console credentials and their generation inputs on adoption. */
export function credentials(env: NodeJS.ProcessEnv = process.env): {
  username: string;
  password?: string;
  passwordHash?: string;
} {
  const value = (name: string): string | undefined => {
    const encoded = env[name + "_B64"];
    if (encoded === undefined) return env[name];
    if (
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
        encoded,
      )
    )
      throw Error("Invalid encoded authentication configuration");
    return Buffer.from(encoded, "base64").toString("utf8");
  };
  const username = value("DASHBOARD_ADMIN_USERNAME"),
    password = value("DASHBOARD_ADMIN_PASSWORD");
  if (username && password) return { username, password };
  const passwordHash = value("DASHBOARD_ADMIN_PASSWORD_HASH");
  if (!username || !passwordHash?.startsWith("$argon2id$"))
    throw Error("Dedicated administrator credentials are required");
  return { username, passwordHash };
}
function equal(a: string, b: string): boolean {
  const left = Buffer.from(a),
    right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}
export async function validateLocalCredentials(
  username: string,
  password: string,
  env: NodeJS.ProcessEnv = process.env,
): Promise<boolean> {
  const expected = credentials(env);
  // Perform the password operation regardless of whether the username matched.
  const passwordOK = expected.passwordHash
    ? await verify(expected.passwordHash, password).catch(() => false)
    : equal(expected.password!, password);
  return equal(username, expected.username) && passwordOK;
}
