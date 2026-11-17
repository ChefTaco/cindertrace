import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { once } from 'node:events';
import { createGateway, sessionCookie } from './ui-gateway.mjs';

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
  for (const name of ['authorization', 'x-forwarded-for', 'x-real-ip']) assert.equal(seen.headers[name], undefined, name);

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
