import { decodeProtectedHeader } from 'jose';
import {
  createOathweaveVerifier as createSharedOathweaveVerifier,
  OathweaveError,
  parseIdentityLinks,
  requireIdentityLink,
  type OathweaveVerifierOptions,
} from '@hivemagnus/hive-common/oathweave';
import type { AuthTokenPayload, UserRole } from '../types/index.js';

export interface OathweaveOptions {
  issuer: string;
  jwksUrl: string;
  userinfoUrl: string;
  audience: string;
}
export interface OathweaveIdentity {
  subject: string;
  issuer: string;
  sessionId: string;
  roles: string[];
  permissions: string[];
  displayName: string;
  authenticatedAt?: number;
  expiresAt?: number;
}
export type OathweaveVerify = (token: string) => Promise<OathweaveIdentity>;

/**
 * Resource JWT validation plus online session revocation, through the shared suite verifier.
 * Only user tokens are accepted. Failure is closed.
 */
export function createOathweaveVerifier(
  options: OathweaveOptions,
  overrides: Pick<OathweaveVerifierOptions, 'keys' | 'fetch' | 'now'> = {},
): OathweaveVerify {
  const verifier = createSharedOathweaveVerifier({
    issuer: options.issuer,
    audience: options.audience,
    jwksUrl: options.jwksUrl,
    userinfoUrl: options.userinfoUrl,
    accept: 'user',
    // Cindertrace has never tolerated clock skew on resource tokens.
    clockToleranceSec: 0,
    // Confirm the identity session online on every use, so revocation is immediate.
    sessionCacheTtlMs: 0,
    ...overrides,
  });
  return async (token) => {
    const principal = await verifier.verifyUser(token);
    // Cindertrace requires the Oathweave `clientId` and `roles` claims to be present.
    if (
      typeof principal.claims['clientId'] !== 'string' ||
      !Array.isArray(principal.claims['roles'])
    )
      throw new OathweaveError('invalid_claims');
    return {
      subject: principal.subject,
      issuer: principal.issuer,
      sessionId: principal.sessionId,
      expiresAt: principal.expiresAt,
      permissions: [...principal.permissions],
      roles: [...principal.roles],
      displayName: principal.displayName,
      ...(principal.authTime !== undefined
        ? { authenticatedAt: principal.authTime * 1000 }
        : {}),
    };
  };
}

let verifier: OathweaveVerify | undefined;
export function configuredOathweaveVerifier(): OathweaveVerify | undefined {
  if (
    !process.env.OATHWEAVE_ISSUER &&
    !process.env.OATHWEAVE_JWKS_URL &&
    !process.env.OATHWEAVE_USERINFO_URL
  )
    return undefined;
  if (!verifier) {
    if (
      !process.env.OATHWEAVE_ISSUER ||
      !process.env.OATHWEAVE_JWKS_URL ||
      !process.env.OATHWEAVE_USERINFO_URL
    )
      throw new Error('Oathweave configuration is incomplete');
    verifier = createOathweaveVerifier({
      issuer: process.env.OATHWEAVE_ISSUER,
      jwksUrl: process.env.OATHWEAVE_JWKS_URL,
      userinfoUrl: process.env.OATHWEAVE_USERINFO_URL,
      audience: 'cindertrace',
    });
  }
  return verifier;
}

const LINK_ROLES = ['ADMIN', 'OPERATOR', 'VIEWER'] as const;
export function linkedSecurityIdentity(
  identity: Pick<OathweaveIdentity, 'issuer' | 'subject' | 'permissions'>,
  raw = process.env['CINDERTRACE_OATHWEAVE_IDENTITIES_JSON'] ?? '[]',
): AuthTokenPayload {
  // A duplicated link grants nothing to that identity; other links keep working.
  const links = parseIdentityLinks(raw, { roles: LINK_ROLES, duplicates: 'ignore' });
  const link = requireIdentityLink(links, identity);
  let role: UserRole;
  if (
    link.role === 'ADMIN' &&
    identity.permissions.includes('cindertrace:admin')
  )
    role = 'ADMIN';
  else if (
    link.role !== 'VIEWER' &&
    identity.permissions.includes('cindertrace:investigate')
  )
    role = 'OPERATOR';
  else if (identity.permissions.includes('cindertrace:view')) role = 'VIEWER';
  else throw new Error('Product permission required');
  return { userId: link.localUserId, email: '', role, iat: 0, exp: 0 };
}
export async function oathweaveAuthentication(
  token: string,
): Promise<AuthTokenPayload | undefined> {
  let algorithm: unknown;
  try {
    algorithm = decodeProtectedHeader(token).alg;
  } catch {
    return undefined;
  }
  if (algorithm !== 'RS256') return undefined;
  const verify = configuredOathweaveVerifier();
  if (!verify) throw new Error('Identity integration is not configured');
  return linkedSecurityIdentity(await verify(token));
}
