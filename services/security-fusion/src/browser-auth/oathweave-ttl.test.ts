import{expect,it}from'vitest';import{spawn}from'node:child_process';import{once}from'node:events';import{mkdtempSync,rmSync}from'node:fs';import{tmpdir}from'node:os';import{join}from'node:path';import{Redis}from'ioredis';import{BrowserSessions}from'./sessions.js';
it('keeps longer resource sessions alive when a shorter session is created for the same linked identity',async()=>{
 const directory=mkdtempSync(join(tmpdir(),'cinder-oauth-ttl-')),socket=join(directory,'redis.sock'),process=spawn('redis-server',['--port','0','--unixsocket',socket,'--save','','--appendonly','no'],{stdio:'ignore'});const redis=new Redis({path:socket,lazyConnect:true,retryStrategy:()=>null});redis.on('error',()=>undefined);
 try{
  for(let i=0;i<60;i++){try{await redis.connect();break}catch{await new Promise(done=>setTimeout(done,50));}}await redis.ping();
  const issuer='https://identity.example.com',subject='synthetic-user',expiresAt=Math.floor(Date.now()/1000)+30;
  const env={SESSION_SECRET:'s'.repeat(64),CINDERTRACE_OATHWEAVE_IDENTITIES_JSON:JSON.stringify([{issuer,subject,localUserId:'retained-admin',role:'ADMIN'}])};
  const service=new BrowserSessions(redis,env,async token=>({issuer,subject,sessionId:'synthetic-sso-session',roles:[],permissions:['cindertrace:admin'],displayName:'Synthetic operator',expiresAt:token==='short-resource'?Math.floor(Date.now()/1000)+3:expiresAt}));
  const long=await service.createOathweave('long-resource'),short=await service.createOathweave('short-resource'),key=service.oathweaveKey(issuer,subject);
  expect(await redis.ttl(key+':generation')).toBeGreaterThan(20);expect(await redis.ttl(key+':sessions')).toBeGreaterThan(20);
  await new Promise(done=>setTimeout(done,3200));expect(await service.verify(short.token)).toBeNull();expect(await service.verify(long.token)).not.toBeNull();
 }finally{await redis.quit().catch(()=>undefined);process.kill('SIGTERM');if(process.exitCode===null)await once(process,'exit');rmSync(directory,{recursive:true,force:true});}
},10000);
