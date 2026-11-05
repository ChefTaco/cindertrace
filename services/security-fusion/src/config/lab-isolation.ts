/** Startup fence for a disposable lab. A source label never grants this capability. */
export function validateLabIsolation(env: NodeJS.ProcessEnv): void {
  if (env['CINDERTRACE_LAB_ENABLED'] !== 'true') return;
  const id = env['CINDERTRACE_LAB_INSTALLATION_ID'];
  if (!id || !/^[a-f0-9]{24}$/.test(id) || env['CINDERTRACE_LAB_CONFIRM'] !== 'isolated-synthetic-installation')
    throw new Error('Lab requires a newly initialized disposable installation');
  if (new URL(env['DATABASE_URL']!).pathname !== `/cindertrace_lab_${id}`)
    throw new Error('Lab requires its dedicated database');
  if (env['SECURITY_APPROVAL_MODE'] !== 'console') throw new Error('Lab requires local human console approval');
  for (const key of ['SECURITY_INGEST_ENABLED', 'SECURITY_DISPATCH_ENABLED', 'SECURITY_NOTIFICATIONS_ENABLED', 'SECURITY_FUSION_UDP_ENABLED', 'TAILSCALE_LOCAL_ENABLED'])
    if (env[key] !== 'false') throw new Error(`Lab requires ${key}=false`);
  for (const [key, value] of Object.entries(env))
    if (!(key === "HIVE_REHEARSAL" && ["true", "false"].includes(value ?? "")) && value && /^(?:HIVE_|OATHWEAVE_|CINDERTRACE_OATHWEAVE_|MAGNUS_|LOKI_|CHATTERMOST_SECURITY_EXPORT_|SECURITY_FUSION_CHATTERMOST_|SECURITY_EXTERNAL_APPROVAL_|SECURITY_SENTI_|SECURITY_APPROVAL_PUBLIC_KEY|SECURITY_APPROVAL_ACTOR|UI_SECURITY_SOURCES_JSON|SECURITY_FUSION_INGEST_SECRET|SECURITY_FUSION_COLLECTOR_CREDENTIALS_JSON)/.test(key))
      throw new Error(`Lab forbids external integration setting ${key}`);
}
