import { afterEach, expect, it, vi } from 'vitest';
import { Hono } from 'hono';
import { SignJWT } from 'jose';
import { createHash } from 'node:crypto';
const fixture = vi.hoisted(() => ({ status:'previewed', hash:'', approval:undefined as any }));
vi.mock('../db/index.js', () => ({ getDb: () => ({
  $transaction: async (fn: any) => fn({
    securityFusionAction: {
      findUnique: async () => ({id:'a1',caseId:'c1',nodeId:'n1',kind:'service_restart',serviceName:'fixture.service',isolationMinutes:null,
        rationale:'recover service',rollbackPlan:'verify health',status:fixture.status,previewSha256:'immutable-hash',previewJson:'{"target":"test-service"}'}),
      updateMany: async ({where,data}: any) => {
        if (!where.status.in.includes(fixture.status)) return {count:0};
        fixture.status=data.status;fixture.hash=data.approvalTokenHash;return {count:1};
      },
    },
    securityFusionActionApproval: {create: async ({data}:any) => {
      fixture.approval=data;
    }},
  }),
}) }));
vi.mock('../services/audit-service.js', () => ({logAuditEvent:vi.fn(),queryAuditEvents:vi.fn()}));
import { securityFusionRouter } from './security-fusion.js';
const app=new Hono();
app.onError((e,c)=>c.json({error:e.message},(e as any).status??500));
app.route('/api/v1/security-fusion',securityFusionRouter);
afterEach(()=>vi.unstubAllEnvs());
it('creates one exact response plan without exposing a console approval token or allowing takeover',async()=>{
  vi.stubEnv('MAGNUS_RESPONSE_URL','https://magnus.example.com/response');
  vi.stubEnv('MAGNUS_RESPONSE_SECRET','test-bridge-secret-'.repeat(3));
  fixture.status='previewed';fixture.approval=undefined;
  const workflow='w'.repeat(40),secret='s'.repeat(40);
  vi.stubEnv('SECURITY_PLUGIN_WORKFLOW_TOKEN_SHA256',createHash('sha256').update(workflow).digest('hex'));
  vi.stubEnv('SECURITY_CONSOLE_TOKEN_SECRET',secret);
  const request=(token:string)=>app.request('/api/v1/security-fusion/actions/a1/request',{method:'POST',headers:{Authorization:'Bearer '+token}});
  let response=await request(workflow);expect(response.status).toBe(200);
  expect((await response.json()).data.approvalToken).toBeUndefined();
  expect((await request(workflow)).status).toBe(409);
  const admin=await new SignJWT({userId:'operator',role:'ADMIN'}).setProtectedHeader({alg:'HS256'}).setIssuer('cindertrace-console').setAudience('cindertrace-api').setIssuedAt().setExpirationTime('60s').sign(new TextEncoder().encode(secret));
  response=await request(admin);expect(response.status).toBe(409);
  expect(fixture.approval.planJson).toContain('security.containment.service_restart');
  expect(fixture.approval.planSha256).toMatch(/^[a-f0-9]{64}$/);
  expect(fixture.approval.requestedBy).toBe('service:security-plugin:aegis-workflow');
  expect(fixture.status).toBe('pending_approval');
  expect((await app.request('/api/v1/security-fusion/actions/a1/approve',{method:'POST',headers:{Authorization:'Bearer '+admin}})).status).toBe(400);
});
