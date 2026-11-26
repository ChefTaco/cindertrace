import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { once } from 'node:events';
import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { createGateway, forwardedFor, sessionCookie } from './ui-gateway.mjs';
import { clientAddress } from '../services/security-fusion/dist/utils/client-address.js';

async function listen(handler) {
  const server = createServer(handler);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return { server, origin: `http://127.0.0.1:${server.address().port}` };
}
function recorder(body) {
  const seen = [];
  return {
    seen,
    handler(req, res) {
      const chunks = [];
      req.on('data', c => chunks.push(c));
      req.on('end', () => {
        seen.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString() });
        res.writeHead(200, { 'content-type': 'application/json', 'set-cookie': 'cindertrace_session=new; HttpOnly', connection: 'keep-alive' });
        res.end(body);
      });
    },
  };
}
function send(origin, path, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((done, fail) => {
    const req = request(origin + path, { method, headers }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => done({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', fail);
    req.end(body);
  });
}

test('keeps only the API session cookie', () => {
  assert.equal(sessionCookie('a=1; cindertrace_session=abc; __Host-oathweave_sso=x'), 'cindertrace_session=abc');
  assert.equal(sessionCookie('other=1'), undefined);
  assert.equal(sessionCookie(undefined), undefined);
  assert.equal(sessionCookie('xcindertrace_session=1'), undefined);
});

test('routes the API, static files and nothing else', async t => {
  const api = recorder('{"ok":true}'), ui = recorder('<html></html>');
  const a = await listen(api.handler), u = await listen(ui.handler);
  const g = await listen(createGateway({ api: a.origin, ui: u.origin }));
  t.after(() => { for (const s of [a, u, g]) s.server.close(); });

  const login = await send(g.origin, '/api/cindertrace/auth/local/login?x=1', {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: 'https://localhost:3444', cookie: 'other=1; cindertrace_session=s1', authorization: 'Bearer leaked', 'x-forwarded-for': '203.0.113.9', 'x-real-ip': '203.0.113.9' },
    body: '{"username":"admin"}',
  });
  assert.equal(login.status, 200);
  assert.equal(login.headers['set-cookie'][0], 'cindertrace_session=new; HttpOnly');
  const seen = api.seen.at(-1);
  assert.equal(seen.url, '/api/v1/auth/local/login?x=1');
  assert.equal(seen.body, '{"username":"admin"}');
  assert.equal(seen.headers.origin, 'https://localhost:3444');
  assert.equal(seen.headers.cookie, 'cindertrace_session=s1');
  for (const name of ['authorization', 'x-real-ip']) assert.equal(seen.headers[name], undefined, name);
  // The caller's value is kept only as a prefix; the gateway's own peer is the last hop.
  assert.equal(seen.headers['x-forwarded-for'], '203.0.113.9, 127.0.0.1');
  assert.equal(seen.headers['x-forwarded-proto'], 'http');

  const page = await send(g.origin, '/security-fusion/cases', { headers: { cookie: 'cindertrace_session=s1', authorization: 'Bearer leaked' } });
  assert.equal(page.status, 200);
  assert.equal(ui.seen.at(-1).url, '/security-fusion/cases');
  assert.equal(ui.seen.at(-1).headers.cookie, undefined);
  assert.equal(ui.seen.at(-1).headers.authorization, undefined);

  // Dot segments cannot climb out of the API prefix, and other API paths are not served.
  await send(g.origin, '/api/cindertrace/../../runtime.json');
  assert.equal(ui.seen.at(-1).url, '/runtime.json');
  await send(g.origin, '/api/cindertrace/%2e%2e/%2e%2e/api/magnus/x');
  assert.equal(api.seen.length, 1);
  for (const path of ['/api/magnus/console/session', '/api/v1/security-fusion/overview', '/api', '/api/cindertrace'])
    assert.equal((await send(g.origin, path)).status, 404, path);
  assert.equal((await send(g.origin, '/index.html', { method: 'POST', body: 'x' })).status, 405);
  assert.equal(api.seen.length, 1);
});

test('answers 502 when an upstream is down', async t => {
  const g = await listen(createGateway({ api: 'http://127.0.0.1:9', ui: 'http://127.0.0.1:9' }));
  t.after(() => g.server.close());
  assert.equal((await send(g.origin, '/api/cindertrace/auth/local/session')).status, 502);
  assert.equal((await send(g.origin, '/')).status, 502);
});

test('refuses origins with paths or credentials', () => {
  assert.throws(() => createGateway({ api: 'https://api:4101/api', ui: 'http://ui:8080' }));
  assert.throws(() => createGateway({ api: 'https://u:p@api:4101', ui: 'http://ui:8080' }));
  assert.throws(() => createGateway({ api: 'ftp://api', ui: 'http://ui:8080' }));
});

test('appends its peer to X-Forwarded-For and bounds the hops', () => {
  assert.equal(forwardedFor(undefined, '::ffff:192.0.2.7'), '192.0.2.7');
  assert.equal(forwardedFor('198.51.100.1 , 198.51.100.2', '192.0.2.7'), '198.51.100.1, 198.51.100.2, 192.0.2.7');
  assert.equal(forwardedFor(['198.51.100.1', '198.51.100.2'], '192.0.2.7'), '198.51.100.1, 198.51.100.2, 192.0.2.7');
  const long = Array.from({ length: 40 }, (_, i) => `198.51.100.${i}`).join(',');
  const hops = forwardedFor(long, '192.0.2.7').split(', ');
  assert.equal(hops.length, 16);
  assert.equal(hops.at(-1), '192.0.2.7');
});

// Regression: every browser request reaches the API from the gateway, so the API must key
// throttling on the client the gateway saw, and never on a caller-written header.
test('API limits are per client behind the gateway, not one shared bucket', { skip: process.platform !== 'linux' && 'needs 127.0.0.0/8 source addresses' }, async t => {
  const limit = 3, counts = new Map();
  const app = new Hono().all('*', async c => {
    const client = await clientAddress(c, { CINDERTRACE_TRUSTED_PROXIES: '127.0.0.1' });
    const count = (counts.get(client) ?? 0) + 1;
    counts.set(client, count);
    return count > limit ? c.json({ error: 'RATE_LIMITED', client }, 429) : c.json({ client });
  });
  const api = serve({ fetch: app.fetch, port: 0, hostname: '127.0.0.1' });
  await once(api, 'listening');
  const apiOrigin = `http://127.0.0.1:${api.address().port}`;
  const g = await listen(createGateway({ api: apiOrigin, ui: apiOrigin }));
  t.after(() => { api.close(); g.server.close(); });
  const call = (localAddress, headers = {}) => new Promise((done, fail) => {
    const req = request(g.origin + '/api/cindertrace/security-fusion/overview', { localAddress, headers, agent: false }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => done({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString()) }));
    });
    req.on('error', fail);
    req.end();
  });
  for (let i = 0; i < limit; i++) assert.equal((await call('127.0.0.2')).status, 200);
  const limited = await call('127.0.0.2');
  assert.equal(limited.status, 429);
  assert.equal(limited.body.client, '127.0.0.2');
  // A forged forwarding header neither escapes the limit nor lands in another bucket.
  const forged = await call('127.0.0.2', { 'x-forwarded-for': '203.0.113.9' });
  assert.equal(forged.status, 429);
  assert.equal(forged.body.client, '127.0.0.2');
  // Another client still gets through.
  const other = await call('127.0.0.3');
  assert.equal(other.status, 200);
  assert.equal(other.body.client, '127.0.0.3');
  assert.equal(counts.has('127.0.0.1'), false);
});
