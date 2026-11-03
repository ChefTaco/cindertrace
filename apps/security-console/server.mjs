// Native TLS boundary: discard caller-controlled forwarding headers.
import http from 'node:http';
import https from 'node:https';
import { readFileSync, existsSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { fileURLToPath } from 'node:url';
if (!process.env.TLS_CERT_PATH || !process.env.TLS_KEY_PATH) throw new Error('TLS certificate and key are required');
for (const name of ['SESSION_SECRET', 'SECURITY_CONSOLE_TOKEN_SECRET']) if (!process.env[name] || process.env[name].length < 32) throw new Error(`${name} must contain at least 32 characters`);
if (process.env.SESSION_SECRET === process.env.SECURITY_CONSOLE_TOKEN_SECRET) throw new Error('Browser sessions and API requests require distinct secrets');
for (const [name, value] of [['DASHBOARD_PUBLIC_ORIGIN', process.env.DASHBOARD_PUBLIC_ORIGIN], ['CINDERTRACE_API_URL', process.env.CINDERTRACE_API_URL ?? process.env.CONTROL_API_URL]]) {
  const url = new URL(value); if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || (url.pathname !== '/')) throw new Error(`${name} must be an HTTPS origin`);
}
if (!process.env.REDIS_URL) throw new Error('REDIS_URL is required for revocable sessions and throttling');
const tls = { cert: readFileSync(process.env.TLS_CERT_PATH), key: readFileSync(process.env.TLS_KEY_PATH) };
http.createServer = (options, listener) => {
  const handler = typeof options === 'function' ? options : listener;
  return https.createServer(typeof options === 'function' ? tls : { ...options, ...tls }, (req, res) => {
    for (const name of ['forwarded', 'x-forwarded-for', 'x-real-ip', 'x-magnus-edge-normalized']) delete req.headers[name];
    const address = req.socket.remoteAddress ?? 'unverified';
    req.headers['x-forwarded-for'] = address; req.headers['x-real-ip'] = address;
    req.headers['x-magnus-edge-normalized'] = '1';
    return handler(req, res);
  });
};
syncBuiltinESMExports();
const staged = new URL('./server.js', import.meta.url);
await import(existsSync(fileURLToPath(staged)) ? staged.href : new URL('./.next/standalone/apps/security-console/server.js', import.meta.url).href);
