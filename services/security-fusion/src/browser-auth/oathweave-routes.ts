import {Hono} from 'hono';
import {rateLimitMiddleware} from '../middleware/rate-limit.js';
import {setCookie} from 'hono/cookie';
import type {AppVariables} from '../types/index.js';
import {browserAuthEnabled,browserSessions,COOKIE_NAME,type BrowserSessions} from './sessions.js';
import {exactBrowserOrigin} from './origin.js';
import {logAuditEvent} from '../services/audit-service.js';
/** Product-owned exchange: no password, account enrollment or console-minted administrator token. */
export function oathweaveBrowserRouter(dependencies:{env?:NodeJS.ProcessEnv;sessions?:()=>Promise<BrowserSessions>;audit?:typeof logAuditEvent}={}) {
 const env=dependencies.env??process.env,router=new Hono<AppVariables>();
 router.use('*',rateLimitMiddleware({max:30,windowMs:60000,keyPrefix:'oathweave-browser-exchange',failClosed:true}));
 router.post('/session',async c=>{
  if(!browserAuthEnabled(env))return c.json({error:'Browser authentication is not configured'},404);
  if(!exactBrowserOrigin(c.req.header('Origin'),env))return c.json({error:'Exact browser origin required'},403);
  const authorization=c.req.header('Authorization')??'';if(!/^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(authorization))return c.json({error:'Oathweave resource token required'},401);
  try {
   const service=await(dependencies.sessions??browserSessions)(),issued=await service.createOathweave(authorization.slice(7));
   const session=await service.verify(issued.token);if(!session)throw Error('Identity verification unavailable');
   try{await(dependencies.audit??logAuditEvent)({action:'auth.login_succeeded',actorId:session.userId!,targetType:'browser-session',targetId:session.userId!,details:{provider:'oathweave',issuer:session.identityIssuer,subject:session.subject}});}catch(error){await service.revoke(session).catch(()=>undefined);throw error;}
   setCookie(c,COOKIE_NAME,issued.token,{secure:true,httpOnly:true,sameSite:'Lax',path:'/',maxAge:issued.ttl});c.header('Cache-Control','no-store');return c.json({ok:true,username:session.username,userId:session.userId,role:session.role,provider:'oathweave'});
  } catch{return c.json({error:'Invalid, inactive or unlinked Oathweave identity'},401);}
 });return router;
}
