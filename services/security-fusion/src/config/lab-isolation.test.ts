import { expect, it } from 'vitest';
import { validateLabIsolation } from './lab-isolation.js';
const id = 'a'.repeat(24);
const env = {CINDERTRACE_LAB_ENABLED: 'true', SECURITY_APPROVAL_MODE: 'console', CINDERTRACE_LAB_INSTALLATION_ID: id, CINDERTRACE_LAB_CONFIRM: 'isolated-synthetic-installation', DATABASE_URL: `postgresql://fixture@localhost/cindertrace_lab_${id}`,
  SECURITY_INGEST_ENABLED: 'false', SECURITY_DISPATCH_ENABLED: 'false', SECURITY_NOTIFICATIONS_ENABLED: 'false', SECURITY_FUSION_UDP_ENABLED: 'false', TAILSCALE_LOCAL_ENABLED: 'false'};
it('requires explicit disposable initialization and a dedicated database', () => {
  expect(() => validateLabIsolation(env)).not.toThrow();
  expect(() => validateLabIsolation({...env, CINDERTRACE_LAB_CONFIRM: ''})).toThrow('disposable');
  expect(() => validateLabIsolation({...env, DATABASE_URL: 'postgresql://fixture@localhost/cindertrace'})).toThrow('dedicated');
});
it.each(['SECURITY_INGEST_ENABLED', 'SECURITY_DISPATCH_ENABLED', 'SECURITY_NOTIFICATIONS_ENABLED', 'SECURITY_FUSION_UDP_ENABLED', 'TAILSCALE_LOCAL_ENABLED'])('refuses an enabled %s in a lab', key => {
  expect(() => validateLabIsolation({...env, [key]: 'true'})).toThrow(key);
});
it.each(['OATHWEAVE_ISSUER', 'CINDERTRACE_OATHWEAVE_IDENTITIES_JSON', 'HIVE_OAUTH_CLIENT_ID', 'MAGNUS_RESPONSE_URL', 'MAGNUS_INVENTORY_TOKEN', 'LOKI_URL', 'CHATTERMOST_SECURITY_EXPORT_TOKEN', 'SECURITY_FUSION_INGEST_SECRET', 'UI_SECURITY_SOURCES_JSON', 'SECURITY_EXTERNAL_APPROVAL_TOKEN_SHA256'])('rejects external setting %s', key => {
  expect(() => validateLabIsolation({...env, [key]: 'fixture'})).toThrow(key);
});

it("permits the explicit read-only rehearsal guard while retaining all external integration fences",()=>{expect(()=>validateLabIsolation({...env,HIVE_REHEARSAL:"true"})).not.toThrow();expect(()=>validateLabIsolation({...env,HIVE_REHEARSAL:"yes"})).toThrow();});
