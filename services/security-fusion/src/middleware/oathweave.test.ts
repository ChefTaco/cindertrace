import { describe, expect, it } from 'vitest';
import { linkedSecurityIdentity } from './oathweave.js';
const identity = {
  issuer: 'https://identity.example.com',
  subject: 'fake-subject',
  sessionId: 'fake-session',
  roles: ['SUPER_ADMIN'],
  permissions: ['cindertrace:investigate'],
  displayName: 'Synthetic User',
};
const link = {
  issuer: identity.issuer,
  subject: identity.subject,
  localUserId: 'existing-user-id',
  role: 'ADMIN',
};
describe('explicit Oathweave security account links', () => {
  it('preserves product identifiers and intersects account role with resource permission', () => {
    expect(
      linkedSecurityIdentity(identity, JSON.stringify([link])),
    ).toMatchObject({ userId: 'existing-user-id', role: 'OPERATOR' });
    expect(
      linkedSecurityIdentity(
        { ...identity, permissions: ['cindertrace:admin'] },
        JSON.stringify([link]),
      ),
    ).toMatchObject({ role: 'ADMIN' });
    expect(
      linkedSecurityIdentity(
        { ...identity, permissions: ['cindertrace:view'] },
        JSON.stringify([link]),
      ),
    ).toMatchObject({ role: 'VIEWER' });
  });
  it('never infers an account link or promotes identity roles', () => {
    expect(() => linkedSecurityIdentity(identity, '[]')).toThrow();
    expect(() =>
      linkedSecurityIdentity(
        identity,
        JSON.stringify([{ ...link, subject: 'other-subject' }]),
      ),
    ).toThrow();
    expect(() =>
      linkedSecurityIdentity(
        { ...identity, permissions: [] },
        JSON.stringify([link]),
      ),
    ).toThrow();
    expect(() =>
      linkedSecurityIdentity(
        { ...identity, permissions: ['cindertrace:admin'] },
        JSON.stringify([{ ...link, role: 'VIEWER' }]),
      ),
    ).toThrow();
    expect(() =>
      linkedSecurityIdentity(identity, JSON.stringify([link, link])),
    ).toThrow();
  });
  it('limits a duplicated link to the duplicated identity', () => {
    const other = { ...link, subject: 'other-subject' };
    expect(
      linkedSecurityIdentity(identity, JSON.stringify([link, other, other])),
    ).toMatchObject({ userId: 'existing-user-id' });
  });
  it('refuses links that name a service actor', () => {
    expect(() =>
      linkedSecurityIdentity(
        identity,
        JSON.stringify([{ ...link, localUserId: 'service:security-plugin:draft' }]),
      ),
    ).toThrow();
  });
});
