import {afterEach,beforeEach,expect,it,vi}from'vitest';
import {generateKeyPair,exportJWK,SignJWT}from'jose';
const state=vi.hoisted(()=>({records:new Map<string,string>()}));
vi.mock('ioredis',()=>({Redis:class{status='ready';on(){}async set(key:string,value:string){state.records.set(key,value);return'OK'}async getdel(key:string){const value=state.records.get(key);state.records.delete(key);return value??null}}}));
import{beginHiveLogin,finishHiveLogin,identityRequestURL}from'./hive-login';
let nonce='',challenge='',idNonce:string|undefined,subject='synthetic-user',resourceSubject='synthetic-user',resourceAudience='cindertrace';
const issuer='https://identity.example.com',client='hivexui-cindertrace-console',backchannel='https://identity-internal.example.com:8443';
let exchanged=0;
beforeEach(async()=>{state.records.clear();nonce='';idNonce=undefined;subject=resourceSubject='synthetic-user';resourceAudience='cindertrace';exchanged=0;
 for(const[k,v]of Object.entries({HIVE_OAUTH_DISCOVERY_URL:issuer+'/oauth/discovery?client_id='+client,HIVE_OAUTH_CLIENT_ID:client,HIVE_OAUTH_ISSUER:issuer,HIVE_OAUTH_API_AUDIENCE:'cindertrace',HIVE_OAUTH_BACKCHANNEL_ORIGIN:backchannel,CINDERTRACE_API_BROWSER_AUTH:'true',DASHBOARD_PUBLIC_ORIGIN:'https://console.example.com',CINDERTRACE_API_URL:'https://security.example.com',SESSION_SECRET:'s'.repeat(64)}))vi.stubEnv(k,v);
 const keys=await generateKeyPair('RS256'),jwk={...await exportJWK(keys.publicKey),kid:'synthetic-key'};
 vi.stubGlobal('fetch',vi.fn<typeof fetch>(async(input,init)=>{const url=String(input);
  if(url===backchannel+'/oauth/discovery?client_id='+client)return Response.json({issuer,authorization_endpoint:issuer+'/auth/authorize',token_endpoint:issuer+'/oauth/token',jwks_uri:issuer+'/oauth/jwks',userinfo_endpoint:issuer+'/oauth/userinfo'});
  if(url===backchannel+'/oauth/jwks')return Response.json({keys:[jwk]});
  if(url===backchannel+'/oauth/token'){
   const form=new URLSearchParams(String(init?.body));expect(form.get('client_secret')).toBeNull();expect(form.get('redirect_uri')).toBe('https://console.example.com/api/auth/hive/callback');const{createHash}=await import('node:crypto');expect(createHash('sha256').update(form.get('code_verifier')!).digest('base64url')).toBe(challenge);
   const resource=await new SignJWT({actorType:'USER'}).setProtectedHeader({alg:'RS256',kid:jwk.kid}).setIssuer(issuer).setSubject(resourceSubject).setAudience(resourceAudience).setIssuedAt().setExpirationTime('5m').sign(keys.privateKey);
   const id=await new SignJWT({nonce:idNonce??nonce}).setProtectedHeader({alg:'RS256',kid:jwk.kid}).setIssuer(issuer).setSubject(subject).setAudience(client).setIssuedAt().setExpirationTime('5m').sign(keys.privateKey);
   return Response.json({access_token:resource,id_token:id,token_type:'Bearer'});
  }
  if(url==='https://security.example.com/api/v1/auth/oathweave/session'){exchanged++;expect(new Headers(init?.headers).get('Origin')).toBe('https://console.example.com');expect(new Headers(init?.headers).get('Authorization')).toMatch(/^Bearer /);return Response.json({ok:true},{headers:{'set-cookie':'cindertrace_session=obviously.fake.session; Path=/; HttpOnly; Secure; SameSite=Lax'}})}
  throw Error('Unexpected transport target');
 }));});
afterEach(()=>{vi.unstubAllEnvs();vi.unstubAllGlobals()});
async function begin(){const flow=await beginHiveLogin(),url=new URL(flow.url);nonce=url.searchParams.get('nonce')!;challenge=url.searchParams.get('code_challenge')!;expect(url.origin).toBe(issuer);expect(url.searchParams.get('code_challenge_method')).toBe('S256');return flow;}
it('uses exact public redirect, nonce and PKCE while keeping credentials on verified server backchannels',async()=>{const flow=await begin();expect(nonce).toHaveLength(43);expect((await finishHiveLogin(flow.state,'synthetic-code')).cookie).toContain('HttpOnly');expect(exchanged).toBe(1);await expect(finishHiveLogin(flow.state,'synthetic-code')).rejects.toThrow(/already consumed/)});
it.each(['nonce','audience','subject'])('refuses changed %s before any product session exchange',async kind=>{const flow=await begin();if(kind==='nonce')idNonce='wrong-nonce';if(kind==='audience')resourceAudience='another-product';if(kind==='subject')resourceSubject='another-person';await expect(finishHiveLogin(flow.state,'synthetic-code')).rejects.toThrow();expect(exchanged).toBe(0)});
it('pins the backchannel to the configured identity origin and HTTPS only',()=>{expect(identityRequestURL(issuer+'/oauth/jwks')).toBe(backchannel+'/oauth/jwks');expect(()=>identityRequestURL('https://another.example.com/jwks')).toThrow();vi.stubEnv('HIVE_OAUTH_BACKCHANNEL_ORIGIN','http://identity-internal.example.com');expect(()=>identityRequestURL(issuer+'/oauth/jwks')).toThrow()});
