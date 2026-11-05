import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, cpSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createServer } from 'node:http';
import { bundleJoseRuntime, runtimeDependencyFile, JOSE_RUNTIME_EXPORTS } from './runtime-dependencies.mjs';
import { secretFindings, privateInfrastructureFindings } from './privacy-policy.mjs';

test('runtime dependency policy preserves legal notices and removes development-only files', () => {
  for (const path of ['LICENSE.md', 'LICENSE.md', 'THIRD_PARTY_NOTICES.md', 'Copyright.txt', 'prebuilds/linux-x64/argon2.node', 'dist/index.js']) assert(runtimeDependencyFile(path));
  for (const path of ['README.md', 'dist/index.d.ts', 'index.d.mts', 'index.d.cts', 'dist/index.js.map', 'project.tsbuildinfo']) assert(!runtimeDependencyFile(path));
});

test('bundled JWT/JWKS runtime preserves signature and claim checks with no privacy findings', async () => {
  const root = resolve(import.meta.dirname, '..');
  const destination = mkdtempSync(join(tmpdir(), 'runtime-jose-fixture-'));
  const source = join(root, 'node_modules/jose');
  let server;
  try {
    mkdirSync(join(destination, 'dist'), {recursive: true});
    cpSync(join(source, 'LICENSE.md'), join(destination, 'LICENSE.md'));
    await bundleJoseRuntime({root, source, destination});
    const code = readFileSync(join(destination, 'dist/index.js'), 'utf8');
    assert.deepEqual([...secretFindings(code), ...privateInfrastructureFindings(code)], []);
    assert.equal(readFileSync(join(destination, 'LICENSE.md'), 'utf8'), readFileSync(join(source, 'LICENSE.md'), 'utf8'));
    const runtime = await import(pathToFileURL(join(destination, 'dist/index.js')).href);
    assert.deepEqual(Object.keys(runtime).sort(), [...JOSE_RUNTIME_EXPORTS].sort());
    const key = crypto.getRandomValues(new Uint8Array(32));
    const signed = await new runtime.SignJWT({role: 'OPERATOR'}).setProtectedHeader({alg: 'HS256'}).setIssuer('fixture-issuer').setAudience('fixture-api').setIssuedAt().setExpirationTime('60s').sign(key);
    const options = {issuer: 'fixture-issuer', audience: 'fixture-api', algorithms: ['HS256'], maxTokenAge: '60s'};
    assert.equal((await runtime.jwtVerify(signed, key, options)).payload.role, 'OPERATOR');
    await assert.rejects(runtime.jwtVerify(signed, crypto.getRandomValues(new Uint8Array(32)), options));
    await assert.rejects(runtime.jwtVerify(signed, key, {...options, issuer: 'wrong-fixture-issuer'}));
    await assert.rejects(runtime.jwtVerify(signed, key, {...options, audience: 'wrong-fixture-api'}));
    await assert.rejects(runtime.jwtVerify(signed, key, {...options, algorithms: ['HS512']}));
    const expired = await new runtime.SignJWT({}).setProtectedHeader({alg: 'HS256'}).setExpirationTime(Math.floor(Date.now() / 1000) - 1).sign(key);
    await assert.rejects(runtime.jwtVerify(expired, key, {algorithms: ['HS256']}));
    const keys = await crypto.subtle.generateKey({name: 'Ed25519'}, true, ['sign', 'verify']);
    const jwk = {...await crypto.subtle.exportKey('jwk', keys.publicKey), kid: 'fixture-key', alg: 'EdDSA', use: 'sig'};
    let healthy = true;
    server = createServer((_req, res) => {res.writeHead(healthy ? 200 : 503, {'content-type': 'application/json'});res.end(JSON.stringify({keys: [jwk]}));});
    await new Promise(done => server.listen(0, '127.0.0.1', done));
    const url = new URL(`http://127.0.0.1:${server.address().port}/jwks`);
    const jwks = runtime.createRemoteJWKSet(url);
    const external = await new runtime.SignJWT({}).setProtectedHeader({alg: 'EdDSA', kid: jwk.kid}).setIssuer('fixture-idp').setAudience('fixture-api').setExpirationTime('60s').sign(keys.privateKey);
    assert.equal((await runtime.jwtVerify(external, jwks, {issuer: 'fixture-idp', audience: 'fixture-api', algorithms: ['EdDSA']})).payload.iss, 'fixture-idp');
    assert.equal(runtime.decodeProtectedHeader(external).kid,jwk.kid);
    let verifiedFetches=0;
    const verifiedKeys=runtime.createRemoteJWKSet(new URL('https://identity.example.com/jwks'),{[runtime.customFetch]:async()=>{verifiedFetches++;return Response.json({keys:[jwk]});}});
    assert.equal((await runtime.jwtVerify(external,verifiedKeys,{issuer:'fixture-idp',audience:'fixture-api',algorithms:['EdDSA']})).payload.iss,'fixture-idp');
    assert.equal(verifiedFetches,1,'The packaged resource verifier retains its verified transport hook');

    const unknown = await new runtime.SignJWT({}).setProtectedHeader({alg: 'EdDSA', kid: 'unknown-fixture-key'}).sign(keys.privateKey);
    await assert.rejects(runtime.jwtVerify(unknown, jwks));
    healthy = false;
    await assert.rejects(runtime.jwtVerify(external, runtime.createRemoteJWKSet(url)));
  } finally {
    if (server) await new Promise(done => {server.close(done);server.closeAllConnections();});
    rmSync(destination, {recursive: true, force: true});
  }
});
