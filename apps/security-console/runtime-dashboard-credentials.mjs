import { existsSync, readFileSync } from 'node:fs';

export const LEGACY_DASHBOARD_CREDENTIALS_DEADLINE = '2026-10-01';
export const DASHBOARD_ADMIN_CREDENTIAL_VERSION = 2;

/** @param {Record<string, string | undefined>} env @param {Date} now */
function legacyFallbackAllowed(env, now = new Date()) {
  return env.ALLOW_LEGACY_DASHBOARD_CREDENTIALS === 'true'
    && now < new Date(`${LEGACY_DASHBOARD_CREDENTIALS_DEADLINE}T00:00:00Z`);
}

/** @param {string | undefined} first @param {string | undefined} second @param {string} message */
function requirePair(first, second, message) {
  if (Boolean(first) !== Boolean(second)) throw new Error(message);
}

/** @param {Record<string, string | undefined>} env @param {string} key */
function credentialValue(env, key) {
  const encoded = env[`${key}_B64`];
  if (encoded != null) {
    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) {
      throw new Error(`${key}_B64 is not valid base64`);
    }
    return Buffer.from(encoded, 'base64').toString('utf8');
  }
  return env[key];
}

/** @param {Record<string, string | undefined>} env @param {Date} now */
export function resolveDashboardLoginCredentials(env = process.env, now = new Date()) {
  const username = credentialValue(env, 'DASHBOARD_ADMIN_USERNAME');
  const password = credentialValue(env, 'DASHBOARD_ADMIN_PASSWORD');
  // A dedicated plaintext admin password takes precedence when configured.
  if (username && password) {
    return { username, password, source: 'dashboard-admin-password', version: DASHBOARD_ADMIN_CREDENTIAL_VERSION };
  }
  const passwordHash = credentialValue(env, 'DASHBOARD_ADMIN_PASSWORD_HASH');
  requirePair(username, passwordHash, 'DASHBOARD_ADMIN_USERNAME and DASHBOARD_ADMIN_PASSWORD (or _HASH) must be configured together');
  if (username && passwordHash) {
    if (!passwordHash.startsWith('$argon2id$')) {
      throw new Error('DASHBOARD_ADMIN_PASSWORD_HASH must be an Argon2id hash');
    }
    return { username, passwordHash, source: 'dashboard-admin-hash', version: DASHBOARD_ADMIN_CREDENTIAL_VERSION };
  }

  // Two-phase compatibility path for installations following the former
  // dedicated-login guidance. SWARM/DEPLOY/SSH credentials are never accepted.
  const legacyUsername = credentialValue(env, 'DASHBOARD_LOGIN_USERNAME');
  const legacyPassword = credentialValue(env, 'DASHBOARD_LOGIN_PASSWORD');
  requirePair(legacyUsername, legacyPassword, 'DASHBOARD_LOGIN_USERNAME and DASHBOARD_LOGIN_PASSWORD must be configured together');
  if (!legacyUsername || !legacyPassword) {
    throw new Error('Dedicated dashboard administrator credentials are required');
  }
  if (now >= new Date(`${LEGACY_DASHBOARD_CREDENTIALS_DEADLINE}T00:00:00Z`)) {
    throw new Error('Legacy dashboard login credentials have expired; configure the dashboard administrator hash');
  }
  for (const key of ['SWARM_PASSWORD', 'DEPLOY_PASSWORD', 'SSH_PASSWORD', 'BOOTSTRAP_SSH_PASSWORD']) {
    if (env[key] && legacyPassword === env[key]) {
      throw new Error(`Dashboard login password must not equal ${key}`);
    }
  }
  return { username: legacyUsername, password: legacyPassword, source: 'legacy-dashboard-login', version: 1 };
}

