import { randomBytes, createHash } from "node:crypto";
import { mkdirSync, writeFileSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { createRequire } from "node:module";
const require = createRequire(
  new URL("../apps/security-console/package.json", import.meta.url),
);
const { hash } = require("argon2");
const root = resolve(process.argv[2] ?? ".");
if (existsSync(resolve(root, ".env")))
  throw new Error(
    "Configuration already exists; refusing to overwrite secrets",
  );
mkdirSync(resolve(root, "certs"), { recursive: true, mode: 0o700 });
mkdirSync(resolve(root, "state"), { recursive: true, mode: 0o700 });
const random = () => randomBytes(32).toString("hex");
const password = random(),
  postgres = random(),
  session = random(),
  consoleSecret = random(),
  audit = random(),
  ingest = random();
const adminHash = await hash(password);
// Dedicated local certificate; use a CA-issued certificate for remote access.
execFileSync(
  "openssl",
  [
    "req",
    "-x509",
    "-newkey",
    "rsa:3072",
    "-nodes",
    "-sha256",
    "-days",
    "90",
    "-subj",
    "/CN=localhost",
    "-addext",
    "subjectAltName=DNS:localhost,DNS:api,DNS:console,IP:127.0.0.1",
    "-keyout",
    resolve(root, "certs/server.key"),
    "-out",
    resolve(root, "certs/server.crt"),
  ],
  { stdio: "pipe" },
);
const env = {
  CINDERTRACE_UID: String(process.getuid?.() ?? 1000),
  CINDERTRACE_GID: String(process.getgid?.() ?? 1000),
  CINDERTRACE_STATE_DIR: "/state",
  POSTGRES_PASSWORD: postgres,
  DATABASE_URL: `postgresql://cindertrace:${postgres}@postgres:5432/cindertrace`,
  REDIS_URL: "redis://redis:6379/0",
  CINDERTRACE_API_URL: "https://api:4101",
  DASHBOARD_PUBLIC_ORIGIN: "https://localhost:3444",
  DASHBOARD_ADMIN_USERNAME: "admin",
  DASHBOARD_ADMIN_PASSWORD_HASH_B64: Buffer.from(adminHash).toString("base64"),
  SESSION_SECRET: session,
  SECURITY_CONSOLE_TOKEN_SECRET: consoleSecret,
  AUDIT_HMAC_SECRET: audit,
  SECURITY_FUSION_RECEIPT_SIGNING_KEY: random(),
  SECURITY_BACKUP_ENCRYPTION_KEY: random(),
  AUTH_RATE_LIMIT_LABEL_KEY: random(),
  SECURITY_FUSION_INGEST_SECRET: ingest,
  SECURITY_FUSION_COLLECTOR_ID: "cindertrace-collector",
  SECURITY_FUSION_COLLECTOR_CREDENTIALS_JSON: JSON.stringify({
    "cindertrace-collector": {
      secret: ingest,
      allowedSources: [
        "unifi_dns",
        "unifi_ids",
        "netflow",
        "wazuh",
        "tailscale",
        "magnus",
        "hive",
        "chattermost",
        "mattermost",
        "magnus_ui",
        "aegis_ui",
        "security_console",
        "cindertrace_ui",
      ],
    },
  }),
  SECURITY_SUMMARY_TOKEN_SHA256: createHash("sha256")
    .update(random())
    .digest("hex"),
  METRICS_TOKEN_SHA256: createHash("sha256").update(random()).digest("hex"),
  SECURITY_WRITES_ENABLED: "true",
  SECURITY_INGEST_ENABLED: "true",
  SECURITY_RETENTION_ENABLED: "true",
  SECURITY_DISPATCH_ENABLED: "false",
  SECURITY_APPROVAL_MODE: "console",
  SECURITY_FUSION_UDP_ENABLED: "false",
  TAILSCALE_LOCAL_ENABLED: "false",
  TLS_CERT_PATH: "/certs/server.crt",
  TLS_KEY_PATH: "/certs/server.key",
  NODE_EXTRA_CA_CERTS: "/certs/server.crt",
  SECURITY_FUSION_EVIDENCE_DIR: "/state/security-fusion/evidence",
  SECURITY_FUSION_STATE_DIR: "/state/collector",
  SECURITY_MIGRATION_HISTORY_DIR: "/state",
  SECURITY_FUSION_RECEIPT_CHAIN_EXPORT: "/state/receipt-heads.jsonl",
  AUDIT_LOG_DIR: "/state/audit-logs",
  UI_SECURITY_LOG_PATH: "/state/ui-security.jsonl",
  SECURITY_BACKUP_STATUS_FILE: "/state/backup-status.json",
};
writeFileSync(
  resolve(root, ".env"),
  Object.entries(env)
    .map(([key, value]) => `${key}=${JSON.stringify(value)}`)
    .join("\n") + "\n",
  { mode: 0o600, flag: "wx" },
);
writeFileSync(
  resolve(root, "state/initial-credentials.txt"),
  `Username: admin\nPassword: ${password}\n`,
  { mode: 0o600, flag: "wx" },
);
console.log(
  "Configuration and TLS certificate created. Initial credentials are in state/initial-credentials.txt.",
);
