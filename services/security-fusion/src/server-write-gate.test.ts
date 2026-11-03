import { afterEach, expect, it, vi } from 'vitest';
import { Hono } from 'hono';
import { securityFusionWriteGate } from './server.js';

afterEach(() => vi.unstubAllEnvs());

it('allows only the exact read-only exposure preview POST while security writes are paused', async () => {
  vi.stubEnv('SECURITY_WRITES_ENABLED', 'false');
  vi.stubEnv('SECURITY_INGEST_ENABLED', 'false');
  const app = new Hono();
  app.use('*', securityFusionWriteGate);
  app.all('*', c => c.json({ reached: true }));
  for (const [method, path, expected] of [
    ['POST', '/api/v1/security-fusion/cases/case-1/assurance/exposure/preview', 200],
    ['POST', '/api/v1/security-fusion/cases/case-1/assurance/exposure', 503],
    ['POST', '/api/v1/security-fusion/cases/case-1/assurance/exposure/preview/extra', 503],
    ['PUT', '/api/v1/security-fusion/cases/case-1/assurance/exposure/preview', 503],
    ['POST', '/api/v1/security-fusion/ingest/events', 503],
    ['GET', '/api/v1/security-fusion/cases/case-1', 200],
  ] as const) {
    const response = await app.request(path, { method });
    expect(response.status, `${method} ${path}`).toBe(expected);
  }
});
