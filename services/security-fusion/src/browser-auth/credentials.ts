import { timingSafeEqualString } from "@hivemagnus/hive-common/secrets";
import { verify } from "argon2";
import { setting, type AliasedSetting } from "../config/settings.js";

/** The local administrator: `CINDERTRACE_ADMIN_*` (or the legacy `DASHBOARD_ADMIN_*`) settings. */
export function credentials(env: NodeJS.ProcessEnv = process.env): {
  username: string;
  password?: string;
  passwordHash?: string;
} {
  const value = (name: AliasedSetting): string | undefined => {
    const encoded = setting(env, (name + "_B64") as AliasedSetting);
    if (encoded === undefined) return setting(env, name);
    if (
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
        encoded,
      )
    )
      throw Error("Invalid encoded authentication configuration");
    return Buffer.from(encoded, "base64").toString("utf8");
  };
  const username = value("CINDERTRACE_ADMIN_USERNAME"),
    password = value("CINDERTRACE_ADMIN_PASSWORD");
  if (username && password) return { username, password };
  const passwordHash = value("CINDERTRACE_ADMIN_PASSWORD_HASH");
  if (!username || !passwordHash?.startsWith("$argon2id$"))
    throw Error("Dedicated administrator credentials are required");
  return { username, passwordHash };
}
const equal = timingSafeEqualString;
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
