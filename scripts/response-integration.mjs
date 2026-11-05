// Explicit synthetic PostgreSQL/API/HTTPS dispatcher drill. Never targets host agents.
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:https';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const database = process.env.CINDERTRACE_TEST_DATABASE_URL ?? '';
if (process.env.CINDERTRACE_RESPONSE_TEST_CONFIRM !== 'isolated-synthetic-installation' ||
    !/^cindertrace_test_response_[a-z0-9_]+$/.test(new URL(database).pathname.slice(1)) ||
    !process.env.CINDERTRACE_TEST_REDIS_URL)
  throw Error('Explicit disposable cindertrace_test_response_* PostgreSQL and Redis fixtures required');

if (!process.env.CINDERTRACE_RESPONSE_TEST_STATE) {
  const state = mkdtempSync(join(tmpdir(), 'cindertrace-response-'));
  try {
    writeFileSync(join(state, 'extensions'), 'subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n');
    const openssl = args => execFileSync('openssl', args, {cwd: state, stdio: 'pipe'});
    openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=Synthetic response fixture CA', '-keyout', 'ca.key', '-out', 'ca.crt']);
    openssl(['req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost', '-keyout', 'server.key', '-out', 'server.csr']);
    openssl(['x509', '-req', '-days', '1', '-in', 'server.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-extfile', 'extensions', '-out', 'server.crt']);
    const child = spawnSync(process.execPath, [import.meta.filename], {stdio: 'inherit', timeout: 180000, env: {
      ...process.env, CINDERTRACE_RESPONSE_TEST_STATE: state, NODE_EXTRA_CA_CERTS: join(state, 'ca.crt'),
    }});
    if (child.error || child.status !== 0) throw Error('Synthetic response drill failed');
  } finally { rmSync(state, {recursive: true, force: true}); }
} else {
  await run();
}

async function run() {
  const state = process.env.CINDERTRACE_RESPONSE_TEST_STATE;
  Object.assign(process.env, {
    DATABASE_URL: database, REDIS_URL: process.env.CINDERTRACE_TEST_REDIS_URL,
    REDIS_PREFIX: 'response-test-' + randomUUID() + ':',
    SECURITY_CONSOLE_TOKEN_SECRET: randomBytes(48).toString('hex'),
    AUDIT_HMAC_SECRET: randomBytes(48).toString('hex'),
    SECURITY_FUSION_RECEIPT_SIGNING_KEY: randomBytes(48).toString('hex'),
    SECURITY_WRITES_ENABLED: 'true', SECURITY_DISPATCH_ENABLED: 'false',
    SECURITY_INGEST_ENABLED: 'false', SECURITY_RETENTION_ENABLED: 'false',
    SECURITY_NOTIFICATIONS_ENABLED: 'false', HIVE_REHEARSAL: 'false',
    CINDERTRACE_LAB_ENABLED: 'false', SECURITY_APPROVAL_MODE: 'native',
    AUDIT_LOG_DIR: join(state, 'audit'), SECURITY_FUSION_EVIDENCE_DIR: join(state, 'evidence'),
    SECURITY_FUSION_RECEIPT_CHAIN_EXPORT: join(state, 'receipts.jsonl'),
    MAGNUS_RESPONSE_SECRET: randomBytes(48).toString('hex'),
    SECURITY_FUSION_RESTART_ALLOWLIST: 'fixture.service',
  });
  execFileSync(process.execPath, ['scripts/apply-migrations.mjs'], {
    cwd: resolve(import.meta.dirname, '../services/security-fusion'), stdio: 'pipe',
  });
  const {getDb, disconnectDb} = await import('../services/security-fusion/dist/db/index.js');
  const {bridgeSignature, equalSignature, responseRequestSchema} = await import('../packages/integrations/dist/index.js');
  const {app} = await import('../services/security-fusion/dist/server.js');
  const {dispatchSecurityFusionOutbox} = await import('../services/security-fusion/dist/services/security-fusion-outbox.js');
  const {SignJWT} = await import('jose');
  const db = getDb();
  const executions = [];
  let mode = 'success';
  const server = createServer({key: readFileSync(join(state, 'server.key')), cert: readFileSync(join(state, 'server.crt'))}, async (req, res) => {
    try {
      let raw = '';
      for await (const chunk of req) {raw += chunk; assert(raw.length < 10000);}
      const time = req.headers['x-cindertrace-time'], nonce = req.headers['x-cindertrace-nonce'];
      assert(Math.abs(Date.now() - Number(time)) < 10000);
      assert(equalSignature(req.headers['x-cindertrace-signature'], bridgeSignature(process.env.MAGNUS_RESPONSE_SECRET, req.method, req.url, time, nonce, raw)));
      let result;
      if (req.method === 'GET' && req.url === '/response/targets/fixture-node/health')
        result = {data: {responseCapable: true, services: [{name: 'fixture.service', status: 'active'}]}};
      else {
        assert.equal(req.method, 'POST'); assert.equal(req.url, '/response/execute');
        const body = responseRequestSchema.parse(JSON.parse(raw));
        assert.equal(body.nodeId, 'fixture-node'); assert.equal(body.serviceName, 'fixture.service');
        assert(body.expiresAt > Date.now());
        executions.push(body);
        if (mode === 'lost-response') {req.socket.destroy(); return;}
        result = {commandId: body.executionId, actionId: body.actionId, nodeId: body.nodeId,
          operation: body.operation, planSha256: body.planSha256, exitCode: 0, receiptSha256: 'a'.repeat(64)};
      }
      const text = JSON.stringify(result);
      res.writeHead(200, {'content-type': 'application/json', 'x-cindertrace-signature': mode === 'bad-receipt' && req.method === 'POST'
        ? '0'.repeat(64) : bridgeSignature(process.env.MAGNUS_RESPONSE_SECRET, 'RESPONSE', req.url, time, nonce, text)});
      res.end(text);
    } catch {res.writeHead(400); res.end();}
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  process.env.MAGNUS_RESPONSE_URL = `https://localhost:${server.address().port}/response`;
  const token = await new SignJWT({userId: 'fixture-admin', role: 'ADMIN'}).setProtectedHeader({alg: 'HS256'})
    .setIssuer('cindertrace-console').setAudience('cindertrace-api').setIssuedAt().setExpirationTime('3m')
    .sign(new TextEncoder().encode(process.env.SECURITY_CONSOLE_TOKEN_SECRET));
  const request = (id, operation, body) => app.request(`/api/v1/security-fusion/actions/${id}/${operation}`, {
    method: 'POST', headers: {authorization: `Bearer ${token}`, 'content-type': 'application/json'},
    ...(body ? {body: JSON.stringify(body)} : {}),
  });
  try {
    assert.equal(await db.securityFusionAction.count(), 0, 'Database must contain no existing response actions');
    await db.securityTarget.create({data: {id: 'fixture-node', name: 'Synthetic fixture', hostname: 'node.example.com',
      baseUrl: 'https://node.example.com', tags: '[]', metadata: '{}', syncedAt: new Date()}});
    const caseRow = await db.securityFusionCase.create({data: {fingerprint: randomUUID(), title: 'Synthetic response drill',
      severity: 'low', confidence: 1, summary: 'No host operations', firstSeenAt: new Date(), lastSeenAt: new Date()}});
    async function proposed() {
      const action = await db.securityFusionAction.create({data: {caseId: caseRow.id, nodeId: 'fixture-node', kind: 'service_restart',
        serviceName: 'fixture.service', rationale: 'Synthetic response protocol fixture', rollbackPlan: 'No host was changed',
        previewJson: '{}', previewSha256: 'b'.repeat(64), requestedBy: 'fixture-admin'}});
      const response = await request(action.id, 'request'); assert.equal(response.status, 200);
      const {plan} = (await response.json()).data;
      return {id: action.id, decision: {confirmed: true, planSha256: plan.plan_sha256, previewSha256: action.previewSha256}};
    }
    async function approved() {const item = await proposed(); assert.equal((await request(item.id, 'approve', item.decision)).status, 200); return item;}
    const expired = await proposed();
    await db.securityFusionActionApproval.update({where: {actionId: expired.id}, data: {expiresAt: new Date(Date.now() - 1)}});
    assert.equal((await request(expired.id, 'approve', expired.decision)).status, 409);
    assert.equal(await db.securityFusionCommandOutbox.count({where: {actionId: expired.id}}), 0);

    const once = await proposed();
    assert.equal((await request(once.id, 'approve', {...once.decision, planSha256: 'c'.repeat(64)})).status, 409);
    const race = await Promise.all([request(once.id, 'approve', once.decision), request(once.id, 'approve', once.decision)]);
    assert.deepEqual(race.map(x => x.status).sort(), [200, 409]);
    process.env.SECURITY_DISPATCH_ENABLED = 'true';
    await Promise.all([dispatchSecurityFusionOutbox(), dispatchSecurityFusionOutbox()]);
    assert.equal(executions.filter(x => x.actionId === once.id).length, 1);
    assert.equal((await db.securityFusionAction.findUniqueOrThrow({where: {id: once.id}})).status, 'succeeded');
    await dispatchSecurityFusionOutbox(); assert.equal(executions.length, 1);

    const queuedExpired = await approved();
    await db.securityFusionApprovalDecision.update({where: {actionId: queuedExpired.id}, data: {expiresAt: new Date(Date.now() - 1)}});
    await dispatchSecurityFusionOutbox();
    assert.equal((await db.securityFusionAction.findUniqueOrThrow({where: {id: queuedExpired.id}})).status, 'failed');
    const changed = await approved();
    await db.securityFusionAction.update({where: {id: changed.id}, data: {previewSha256: 'd'.repeat(64)}});
    await dispatchSecurityFusionOutbox(); assert.equal(executions.length, 1);
    assert.equal((await db.securityFusionAction.findUniqueOrThrow({where: {id: changed.id}})).status, 'failed');

    for (const failure of ['lost-response', 'bad-receipt']) {
      const item = await approved(); mode = failure;
      await dispatchSecurityFusionOutbox(); mode = 'success';
      assert.equal((await db.securityFusionAction.findUniqueOrThrow({where: {id: item.id}})).status, 'unknown');
      assert.equal((await db.securityExecution.findUniqueOrThrow({where: {actionId_operation: {actionId: item.id, operation: 'execute'}}})).status, 'unknown');
      await dispatchSecurityFusionOutbox();
      assert.equal((await request(item.id, 'approve', item.decision)).status, 409);
      assert.equal(executions.filter(x => x.actionId === item.id).length, 1);
    }
    const interrupted = await approved(), commandId = randomUUID();
    await db.$transaction([
      db.securityFusionCommandOutbox.update({where: {actionId_operation: {actionId: interrupted.id, operation: 'execute'}},
        data: {status: 'dispatching', remoteCommandId: commandId, attempts: 1, leaseExpiresAt: new Date(Date.now() - 1)}}),
      db.securityFusionAction.update({where: {id: interrupted.id}, data: {status: 'executing'}}),
      db.securityExecution.create({data: {id: commandId, actionId: interrupted.id, operation: 'execute', nodeId: 'fixture-node', status: 'started'}}),
    ]);
    await dispatchSecurityFusionOutbox(); await dispatchSecurityFusionOutbox();
    assert.equal((await db.securityFusionAction.findUniqueOrThrow({where: {id: interrupted.id}})).status, 'unknown');
    assert.equal(executions.filter(x => x.actionId === interrupted.id).length, 0);
    // A fresh dispatcher process must honor the terminal durable rows as well.
    execFileSync(process.execPath, ['--input-type=module', '-e', `
      const {dispatchSecurityFusionOutbox}=await import('./services/security-fusion/dist/services/security-fusion-outbox.js');
      const {disconnectDb}=await import('./services/security-fusion/dist/db/index.js');
      try {if(await dispatchSecurityFusionOutbox()!==0)throw Error('Terminal effect replayed');}
      finally {await disconnectDb();}
    `], {cwd: resolve(import.meta.dirname, '..'), stdio: 'pipe', timeout: 15000});
    assert.equal(executions.length, 3);
    console.log(JSON.stringify({responseIntegration: 'passed', realPostgreSQL: true, signedVerifiedHttps: true,
      exactPlan: true, expiryBeforeApproval: true, expiryBeforeDispatch: true, oneUseConcurrentApproval: true,
      oneDispatch: true, lostResponseNeverReplayed: true, unsignedReceiptUnknown: true, expiredClaimNeverReplayed: true,
      freshDispatcherRespectsDurableOutcomes: true, executionRequests: executions.length, hostOperations: 0}));
  } finally {
    server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await disconnectDb();
    const {closeRateLimitRedis} = await import('../services/security-fusion/dist/middleware/rate-limit.js');
    await closeRateLimitRedis();
  }
}
