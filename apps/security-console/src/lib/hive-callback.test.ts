import{afterEach,expect,it,vi}from'vitest';import{NextRequest}from'next/server';
vi.mock('@/lib/hive-login',()=>({finishHiveLogin:vi.fn(async()=>({cookie:'cindertrace_session=obviously.fake.session; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=240'}))}));
vi.mock('@/lib/security-events',()=>({recordSecurityEvent:vi.fn().mockResolvedValue(undefined)}));
import{GET}from'../app/api/auth/hive/callback/route';import{finishHiveLogin}from'./hive-login';
afterEach(()=>{vi.unstubAllEnvs();vi.clearAllMocks()});
it('forwards the API-owned cookie alongside state deletion without leaking identity bearer tokens',async()=>{vi.stubEnv('DASHBOARD_PUBLIC_ORIGIN','https://console.example.com');vi.stubEnv('HIVE_OAUTH_ISSUER','https://identity.example.com');const state='s'.repeat(43),req=new NextRequest('https://console.example.com/api/auth/hive/callback?state='+state+'&code=synthetic-code&iss=https%3A%2F%2Fidentity.example.com',{headers:{cookie:'cindertrace_hive_state='+state}});const response=await GET(req);expect(response.status).toBe(307);expect(response.headers.get('location')).toBe('https://console.example.com/');const cookies=response.headers.getSetCookie();expect(cookies.some(value=>value.startsWith('cindertrace_session=')&&value.includes('HttpOnly'))).toBe(true);expect(cookies.some(value=>value.startsWith('cindertrace_hive_state=')&&value.includes('Max-Age=0'))).toBe(true);expect(response.headers.get('cache-control')).toBe('no-store');});
it('refuses a missing state cookie before any token exchange',async()=>{expect((await GET(new NextRequest('https://console.example.com/api/auth/hive/callback?state='+ 's'.repeat(43)+'&code=synthetic-code'))).status).toBe(401);expect(finishHiveLogin).not.toHaveBeenCalled()});

it.each(['state','code','iss'])('rejects duplicate %s and an issuer mix-up before exchange',async key=>{vi.stubEnv('HIVE_OAUTH_ISSUER','https://identity.example.com');const state='s'.repeat(43),base='https://console.example.com/api/auth/hive/callback?state='+state+'&code=synthetic-code&iss=https%3A%2F%2Fidentity.example.com';const duplicate=new NextRequest(base+'&'+key+'=duplicate',{headers:{cookie:'cindertrace_hive_state='+state}});expect((await GET(duplicate)).status).toBe(401);const wrong=new NextRequest(base.replace('identity.example.com','another.example.com'),{headers:{cookie:'cindertrace_hive_state='+state}});expect((await GET(wrong)).status).toBe(401);expect(finishHiveLogin).not.toHaveBeenCalled()});

function validCallback() {
  const state = 's'.repeat(43);
  return new NextRequest('https://console.example.com/api/auth/hive/callback?state='+state+'&code=synthetic-code&iss=https%3A%2F%2Fidentity.example.com', {headers:{cookie:'cindertrace_hive_state='+state}});
}
it('lands on the configured console path while preserving the configured origin',async()=>{
  vi.stubEnv('DASHBOARD_PUBLIC_ORIGIN','https://console.example.com');
  vi.stubEnv('HIVE_OAUTH_ISSUER','https://identity.example.com');
  vi.stubEnv('DASHBOARD_LOGIN_RETURN_PATH','/security-fusion');
  const response=await GET(validCallback());
  expect(response.status).toBe(307);
  expect(response.headers.get('location')).toBe('https://console.example.com/security-fusion');
  expect(finishHiveLogin).toHaveBeenCalledOnce();
});
it.each(['','https://outside.example.com','//outside.example.com','/\\outside.example.com','/security-fusion?next=https://outside.example.com','/security-fusion#fragment','/security-fusion/../login','/./security-fusion','/%2f%2foutside.example.com','/%252foutside.example.com','/security-fusion/%2e%2e/login','/security-fusion//login','/security-fusion\n','/'+ 'a'.repeat(2048)])('refuses unsafe configured landing path %j before exchanging the authorization code',async path=>{
  vi.stubEnv('DASHBOARD_PUBLIC_ORIGIN','https://console.example.com');
  vi.stubEnv('HIVE_OAUTH_ISSUER','https://identity.example.com');
  vi.stubEnv('DASHBOARD_LOGIN_RETURN_PATH',path);
  expect((await GET(validCallback())).status).toBe(401);
  expect(finishHiveLogin).not.toHaveBeenCalled();
});
it.each(['http://console.example.com','https://user@console.example.com','https://console.example.com/nested','https://console.example.com?next=elsewhere'])('refuses an unsafe dashboard origin before authorization code exchange',async origin=>{
  vi.stubEnv('DASHBOARD_PUBLIC_ORIGIN',origin);
  vi.stubEnv('HIVE_OAUTH_ISSUER','https://identity.example.com');
  expect((await GET(validCallback())).status).toBe(401);
  expect(finishHiveLogin).not.toHaveBeenCalled();
});
