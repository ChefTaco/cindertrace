import { describe, expect, it } from 'vitest';
import { generateKeyPair, SignJWT, type JWTPayload } from 'jose';
import {
  loadOathweaveVectors,
  runOathweaveConformance,
} from '@hivemagnus/hive-common/oathweave/conformance';
import { createOathweaveVerifier } from './oathweave.js';

describe('Oathweave resource verifier', () => {
  it('meets the shared Oathweave conformance vectors for user tokens', async () => {
    const vectors = await loadOathweaveVectors();
    const report = await runOathweaveConformance(
      (token, ctx) =>
        createOathweaveVerifier(
          {
            issuer: ctx.issuer,
            audience: ctx.audience,
            jwksUrl: ctx.jwksUrl,
            userinfoUrl: ctx.userinfoUrl,
          },
          { fetch: ctx.fetch, now: () => ctx.nowMs },
        )(token),
      {
        strictReasons: true,
        // Cindertrace accepts people only; the service vector is checked below.
        only: vectors.vectors
          .filter((vector) => vector.principal === 'user')
          .map((vector) => vector.name),
      },
    );
    expect(report.failed).toBe(0);
    expect(report.passed).toBe(
      vectors.vectors.filter((vector) => vector.principal === 'user').length,
    );
  });

  it('refuses the valid service-account vector', async () => {
    const vectors = await loadOathweaveVectors();
    const service = vectors.vectors.find((vector) => vector.name === 'valid-service')!;
    const report = await runOathweaveConformance(
      (token, ctx) =>
        createOathweaveVerifier(
          {
            issuer: ctx.issuer,
            audience: ctx.audience,
            jwksUrl: ctx.jwksUrl,
            userinfoUrl: ctx.userinfoUrl,
          },
          { fetch: ctx.fetch, now: () => ctx.nowMs },
        )(token),
      {
        only: [service.name],
        throwOnFailure: false,
        vectors: { ...vectors, vectors: [service] },
      },
    );
    expect(report.results[0]).toMatchObject({ actual: 'reject' });
  });

  describe('product rules kept from the previous verifier', () => {
    const issuer = 'https://identity.example.com';
    const options = {
      issuer,
      audience: 'cindertrace',
      jwksUrl: `${issuer}/jwks`,
      userinfoUrl: `${issuer}/userinfo`,
    };
    const setup = async () => {
      const keys = await generateKeyPair('RS256');
      let calls = 0;
      let active = true;
      const verify = createOathweaveVerifier(options, {
        keys: async () => keys.publicKey,
        fetch: async () => {
          calls += 1;
          return Response.json(
            active ? { sub: 'synthetic-subject', name: 'Synthetic User' } : {},
            { status: active ? 200 : 401 },
          );
        },
      });
      const sign = (claims: JWTPayload = {}, at = Math.floor(Date.now() / 1000)) =>
        new SignJWT({
          actorType: 'USER',
          clientId: 'synthetic-client',
          sessionId: 'synthetic-session',
          permissions: ['cindertrace:view'],
          roles: ['VIEWER'],
          auth_time: at - 30,
          ...claims,
        })
          .setProtectedHeader({ alg: 'RS256' })
          .setIssuer(issuer)
          .setSubject('synthetic-subject')
          .setAudience('cindertrace')
          .setJti('synthetic-token')
          .setIssuedAt(at)
          .setExpirationTime(at + 300)
          .sign(keys.privateKey);
      return {
        verify,
        sign,
        calls: () => calls,
        revoke: () => {
          active = false;
        },
      };
    };

    it('returns the identity with the authentication time in milliseconds', async () => {
      const { verify, sign } = await setup();
      const at = Math.floor(Date.now() / 1000);
      expect(await verify(await sign({}, at))).toMatchObject({
        subject: 'synthetic-subject',
        issuer,
        sessionId: 'synthetic-session',
        roles: ['VIEWER'],
        permissions: ['cindertrace:view'],
        displayName: 'Synthetic User',
        authenticatedAt: (at - 30) * 1000,
        expiresAt: at + 300,
      });
    });

    it('requires the roles and clientId claims', async () => {
      const { verify, sign } = await setup();
      await expect(verify(await sign({ roles: undefined }))).rejects.toMatchObject({
        reason: 'invalid_claims',
      });
      await expect(
        verify(await sign({ clientId: undefined, client_id: 'synthetic-client' })),
      ).rejects.toMatchObject({ reason: 'invalid_claims' });
    });

    it('tolerates no clock skew', async () => {
      const { verify, sign } = await setup();
      const future = Math.floor(Date.now() / 1000) + 20;
      await expect(verify(await sign({}, future))).rejects.toMatchObject({
        reason: 'not_yet_valid',
      });
    });

    it('checks the identity session online on every use', async () => {
      const { verify, sign, calls, revoke } = await setup();
      const token = await sign();
      await verify(token);
      await verify(token);
      expect(calls()).toBe(2);
      revoke();
      await expect(verify(token)).rejects.toMatchObject({ reason: 'session_inactive' });
    });

    it('refuses plain-http endpoints at startup', () => {
      expect(() =>
        createOathweaveVerifier({ ...options, jwksUrl: 'http://identity.example.com/jwks' }),
      ).toThrow(/https/);
    });
  });
});
