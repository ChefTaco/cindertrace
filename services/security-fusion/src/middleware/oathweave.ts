import { z } from 'zod';
import { decodeProtectedHeader } from 'jose';
import {
  configuredOathweaveVerifier,
  type OathweaveIdentity,
} from './oathweave-verifier.js';
import type { AuthTokenPayload, UserRole } from '../types/index.js';

const linkSchema = z
  .object({
    issuer: z.url(),
    subject: z.string().min(1).max(256),
    localUserId: z.string().min(1).max(256),
    role: z.enum(['ADMIN', 'OPERATOR', 'VIEWER']),
  })
  .strict();
export function linkedSecurityIdentity(
  identity: OathweaveIdentity,
  raw = process.env['CINDERTRACE_OATHWEAVE_IDENTITIES_JSON'] ?? '[]',
): AuthTokenPayload {
  const links = z.array(linkSchema).max(10000).parse(JSON.parse(raw));
  const matches = links.filter(
    (link) =>
      link.issuer === identity.issuer && link.subject === identity.subject,
  );
  if (matches.length !== 1)
    throw new Error('An explicit unique product account link is required');
  const link = matches[0]!;
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
