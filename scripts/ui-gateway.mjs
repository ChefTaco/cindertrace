// HiveXUI gateway for standalone and lab installations. It is the only published service:
// TLS at DASHBOARD_PUBLIC_ORIGIN, HiveXUI's static files from the internal `ui` service, and
// /api/cindertrace/* to the API's /api/v1/*. It holds no product secret and adds no identity:
// the API authenticates every request itself from its own `cindertrace_session` cookie.
import { createServer as createHttpsServer } from 'node:https';
import { Agent as HttpAgent, request as httpRequest } from 'node:http';
import { Agent as HttpsAgent, request as httpsRequest } from 'node:https';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

export const API_PREFIX = '/api/cindertrace/';
export const SESSION_COOKIE = 'cindertrace_session';
// Request headers a browser needs to reach each upstream. Everything else, including
// Authorization, forwarding headers and other cookies, stays at the gateway.
const STATIC_HEADERS = ['accept', 'accept-encoding', 'accept-language', 'if-modified-since', 'if-none-match', 'range', 'user-agent'];
const API_HEADERS = [...STATIC_HEADERS, 'content-length', 'content-type', 'origin', 'x-request-id'];
// Hop-by-hop response headers are the gateway's own connection's business.
const HOP = new Set(['connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'trailer', 'te']);

function upstream(origin, name) {
  const url = new URL(origin);
  if (!['http:', 'https:'].includes(url.protocol) || url.pathname !== '/' || url.search || url.username || url.password)
    throw Error(`${name} must be a bare http(s) origin`);
  const secure = url.protocol === 'https:';
  return { url, request: secure ? httpsRequest : httpRequest, agent: new (secure ? HttpsAgent : HttpAgent)({ keepAlive: true }) };
}

function pick(headers, names) {
  const out = {};
  for (const name of names) if (headers[name] !== undefined) out[name] = headers[name];
  return out;
}

/** Keep only the API's session cookie; a request without it carries no Cookie header. */
export function sessionCookie(header) {
  if (!header) return undefined;
  const kept = String(header).split(/;\s*/).filter(part => part.startsWith(SESSION_COOKIE + '='));
  return kept.length ? kept.join('; ') : undefined;
}

function reply(res, status, body = '') {
  res.writeHead(status, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  res.end(body);
}

/** Request handler. `api` and `ui` are origins such as https://api:4101 and http://ui:8080. */
export function createGateway({ api, ui, timeoutMs = 120_000 }) {
  const apiUpstream = upstream(api, 'API origin'), uiUpstream = upstream(ui, 'UI origin');
  function forward(req, res, target, path, headers) {
    const outgoing = target.request({
      host: target.url.hostname, port: target.url.port || undefined, servername: target.url.hostname,
      method: req.method, path, agent: target.agent, timeout: timeoutMs,
      headers: { ...headers, host: target.url.host },
    }, answer => {
      const kept = {};
      for (const [name, value] of Object.entries(answer.headers)) if (!HOP.has(name)) kept[name] = value;
      res.writeHead(answer.statusCode ?? 502, kept);
      answer.pipe(res);
      answer.on('error', () => res.destroy());
    });
    outgoing.on('timeout', () => outgoing.destroy(Error('upstream timeout')));
    outgoing.on('error', () => {
      if (!res.headersSent) reply(res, 502, 'Upstream unavailable');
      else res.destroy();
    });
    req.on('aborted', () => outgoing.destroy());
    req.pipe(outgoing);
  }
  return function handle(req, res) {
    // Origin-form targets only; the URL parser removes dot segments (including encoded ones).
    if (!req.url?.startsWith('/') || req.url.startsWith('//')) return reply(res, 400, 'Bad request');
    let url;
    try { url = new URL(req.url, 'https://gateway.invalid'); } catch { return reply(res, 400, 'Bad request'); }
    if (url.pathname.startsWith(API_PREFIX)) {
      const headers = pick(req.headers, API_HEADERS);
      const cookie = sessionCookie(req.headers.cookie);
      if (cookie) headers.cookie = cookie;
      if (req.headers['transfer-encoding'] && headers['content-length'] === undefined) headers['transfer-encoding'] = 'chunked';
      return forward(req, res, apiUpstream, '/api/v1/' + url.pathname.slice(API_PREFIX.length) + url.search, headers);
    }
    if (url.pathname === '/api' || url.pathname.startsWith('/api/')) return reply(res, 404, 'Not found');
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.setHeader('allow', 'GET, HEAD');
      return reply(res, 405, 'Method not allowed');
    }
    return forward(req, res, uiUpstream, url.pathname + url.search, pick(req.headers, STATIC_HEADERS));
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const env = process.env;
  const api = env.CINDERTRACE_API_URL ?? 'https://api:4101';
  if (new URL(api).protocol !== 'https:') throw Error('The gateway reaches the API only over verified HTTPS');
  if (!env.TLS_CERT_PATH || !env.TLS_KEY_PATH) throw Error('TLS_CERT_PATH and TLS_KEY_PATH are required');
  const port = Number(env.CINDERTRACE_GATEWAY_PORT ?? 3444);
  const handler = createGateway({ api, ui: env.CINDERTRACE_UI_UPSTREAM ?? 'http://ui:8080' });
  const server = createHttpsServer({ cert: readFileSync(env.TLS_CERT_PATH), key: readFileSync(env.TLS_KEY_PATH), minVersion: 'TLSv1.2' }, handler);
  server.headersTimeout = 30_000;
  server.requestTimeout = 300_000;
  server.listen(port, env.CINDERTRACE_GATEWAY_HOST ?? '0.0.0.0', () => console.log(JSON.stringify({ gateway: 'listening', port })));
  for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => server.close(() => process.exit(0)));
}
