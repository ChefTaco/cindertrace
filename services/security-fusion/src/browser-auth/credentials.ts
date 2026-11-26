import { timingSafeEqualString } from "@hivemagnus/hive-common/secrets";
import { verify } from "argon2";
import { z } from "zod";
import { base32Decode } from "./totp.js";
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

export type LocalRole = "ADMIN" | "OPERATOR" | "VIEWER";
/** A local sign-in account: the administrator, or one of CINDERTRACE_LOCAL_ACCOUNTS_JSON. */
export interface LocalAccount {
  username: string;
  userId: string;
  role: LocalRole;
  password?: string;
  passwordHash?: string;
  totpSecret?: Buffer;
  /** The account configured by the CINDERTRACE_ADMIN_* (or DASHBOARD_ADMIN_*) settings. */
  administrator: boolean;
}

const Account = z
  .object({
    username: z.string().min(1).max(256).refine((value) => !/[\0\r\n]/.test(value)),
    passwordHash: z.string().startsWith("$argon2id$").max(1024),
    role: z.enum(["ADMIN", "OPERATOR", "VIEWER"]),
    userId: z.string().regex(/^[A-Za-z0-9._:@-]{1,128}$/).optional(),
    totpSecret: z.string().max(256).optional(),
  })
  .strict();

function totpSecret(value: string | undefined, name: string): Buffer | undefined {
  if (!value) return undefined;
  let secret: Buffer;
  try {
    secret = base32Decode(value);
  } catch {
    throw Error(`${name}: the TOTP secret is not base32`);
  }
  if (secret.length < 16) throw Error(`${name}: the TOTP secret must be at least 128 bits`);
  return secret;
}

let accountCache: { key: string; accounts: LocalAccount[] } | undefined;
/**
 * Every local account. CINDERTRACE_LOCAL_ACCOUNTS_JSON (or its base64 form `_B64`, which
 * keeps the `$` of Argon2id hashes away from Compose interpolation) adds accounts beyond the
 * administrator: `[{"username","passwordHash","role","userId"?,"totpSecret"?}]`. Usernames
 * and user IDs must be unique. Startup validation calls this, so a bad value stops the API.
 */
export function localAccounts(env: NodeJS.ProcessEnv = process.env): LocalAccount[] {
  const admin = credentials(env);
  const adminTotp = env["CINDERTRACE_ADMIN_TOTP_SECRET"];
  const encoded = env["CINDERTRACE_LOCAL_ACCOUNTS_JSON_B64"];
  const raw = encoded !== undefined ? Buffer.from(encoded, "base64").toString("utf8") : env["CINDERTRACE_LOCAL_ACCOUNTS_JSON"] ?? "[]";
  const key = JSON.stringify([admin, adminTotp ?? "", raw, setting(env, "CINDERTRACE_ADMIN_ACCOUNT_ID") ?? ""]);
  if (accountCache?.key === key) return accountCache.accounts;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw Error("CINDERTRACE_LOCAL_ACCOUNTS_JSON is not valid JSON");
  }
  const list = z.array(Account).max(100).safeParse(parsed);
  if (!list.success) throw Error("CINDERTRACE_LOCAL_ACCOUNTS_JSON must list {username, passwordHash, role} accounts");
  const accounts: LocalAccount[] = [
    {
      ...admin,
      userId: setting(env, "CINDERTRACE_ADMIN_ACCOUNT_ID") ?? admin.username,
      role: "ADMIN",
      ...(adminTotp ? { totpSecret: totpSecret(adminTotp, "CINDERTRACE_ADMIN_TOTP_SECRET")! } : {}),
      administrator: true,
    },
    ...list.data.map((entry, index) => ({
      username: entry.username,
      userId: entry.userId ?? "local:" + entry.username,
      role: entry.role,
      passwordHash: entry.passwordHash,
      ...(entry.totpSecret ? { totpSecret: totpSecret(entry.totpSecret, `CINDERTRACE_LOCAL_ACCOUNTS_JSON[${index}]`)! } : {}),
      administrator: false,
    })),
  ];
  const usernames = new Set(accounts.map((account) => account.username));
  const userIds = new Set(accounts.map((account) => account.userId));
  if (usernames.size !== accounts.length || userIds.size !== accounts.length)
    throw Error("Local account usernames and user IDs must be unique");
  accountCache = { key, accounts };
  return accounts;
}

/** The account a username names, compared in constant time against every account. */
export function localAccount(username: string, env: NodeJS.ProcessEnv = process.env): LocalAccount | undefined {
  let found: LocalAccount | undefined;
  for (const account of localAccounts(env)) if (equal(username, account.username) && !found) found = account;
  return found;
}

/**
 * The account whose username and password match, or null. A password operation runs even
 * for an unknown username, so timing does not reveal which usernames exist.
 */
export async function authenticateLocal(
  username: string,
  password: string,
  env: NodeJS.ProcessEnv = process.env,
): Promise<LocalAccount | null> {
  const account = localAccount(username, env);
  let passwordOK: boolean;
  if (account?.password !== undefined) passwordOK = equal(account.password, password);
  else if (account?.passwordHash) passwordOK = await verify(account.passwordHash, password).catch(() => false);
  else {
    // Unknown username: spend the same work against a configured hash (the result is
    // discarded), so timing does not reveal which usernames exist.
    const decoy = localAccounts(env).find((candidate) => candidate.passwordHash)?.passwordHash;
    if (decoy) await verify(decoy, password).catch(() => false);
    else equal(localAccounts(env)[0]!.password ?? "", password);
    passwordOK = false;
  }
  return account && passwordOK ? account : null;
}

export async function validateLocalCredentials(
  username: string,
  password: string,
  env: NodeJS.ProcessEnv = process.env,
): Promise<boolean> {
  return Boolean(await authenticateLocal(username, password, env));
}
