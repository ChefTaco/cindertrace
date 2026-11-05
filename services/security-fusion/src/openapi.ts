import { securityBrowserRoutes } from "@cindertrace/contracts/browser";
import { z } from "zod";
import {
  localBrowserLoginSchema,localBrowserProfileSchema,
  labTransitionSchema, labDecisionSchema,
  securityFusionEventBatchSchema,
  securityFusionSourceReportSchema,
  securityFusionInvestigationDraftSchema,
  securityFusionContainmentPreviewSchema,
} from "@cindertrace/contracts";
import { securityFusionRouter } from "./routes/security-fusion.js";
import { adminDecisionSchema } from "./services/approval-decisions.js";
import { sentiApprovalAssertionSchema } from "./security/senti-approval.js";
export function buildOpenApiSpec() {
  const paths: Record<string, Record<string, unknown>> = {};
  for (const route of securityFusionRouter.routes) {
    if (route.method === "ALL") continue;
    const path =
      "/api/v1/security-fusion" + route.path.replace(/:([a-zA-Z]+)/g, "{$1}");
    const method = route.method.toLowerCase();
    const schema =
      /^\/lab\/runs\/:id\/(advance|complete)$/.test(route.path) ? labTransitionSchema
        : method === 'post' && (route.path === '/lab/runs' || route.path.endsWith('/restart')) ? z.object({}).strict()
        : route.path.endsWith('/decision') && route.path.startsWith('/lab/') ? labDecisionSchema
        : route.path === "/ingest/events"
        ? securityFusionEventBatchSchema
        : route.path === "/ingest/source-status"
          ? securityFusionSourceReportSchema
          : route.path.endsWith("/investigations") && method === "post"
            ? securityFusionInvestigationDraftSchema
            : route.path.endsWith("/actions/preview")
              ? securityFusionContainmentPreviewSchema
              : /\/actions\/:id\/(approve|reject)$/.test(route.path)
                ? adminDecisionSchema
                : route.path === "/approval-decisions"
                  ? sentiApprovalAssertionSchema
                  : null;
    (paths[path] ??= {})[method] = {
      summary: `${route.method} ${route.path}`,
      tags: ["Security Fusion"],
      security: route.path.startsWith("/ingest/")
        ? [{ collectorSignature: [] }]
        : [{ bearerAuth: [] }],
      ...(schema
        ? {
            requestBody: {
              required: true,
              content: {
                "application/json": { schema: z.toJSONSchema(schema) },
              },
            },
          }
        : {}),
      parameters: [...path.matchAll(/\{([^}]+)\}/g)].map((match) => ({
        name: match[1],
        in: "path",
        required: true,
        schema: { type: "string" },
      })),
      responses: {
        200: { description: "Successful response" },
        202: { description: "Accepted signed observations" },
        400: { description: "Invalid input" },
        401: { description: "Missing or invalid credentials" },
        403: { description: "Scope or role denied" },
        409: { description: "State, policy, or replay conflict" },
        503: { description: "Capability unavailable or writes paused" },
      },
    };
  }
  for(const route of securityBrowserRoutes) {
    const operation=paths["/api/v1/security-fusion"+route.path]?.[route.method.toLowerCase()] as {responses:Record<string,unknown>}|undefined;
    if(!operation)throw Error('Missing owned browser route in OpenAPI: '+route.method+' '+route.path);
    const created=route.method==='POST'&&(/\/(investigations|preserve|restart)$/.test(route.path)||route.path==='/lab/runs');
    const status=created?'201':route.method==='POST'&&route.path.endsWith('/release')?'202':'200';
    operation.responses[status]={description:'Product-owned browser response',content:{'application/json':{schema:z.toJSONSchema(z.object({success:z.literal(true),data:route.response}))}}};
  }
  const localAuthResponses={401:{description:"Invalid credentials or absent/revoked session"},403:{description:"Exact browser origin required"},429:{description:"Durable admission limit reached"},503:{description:"Authentication or audit storage unavailable"}};
  paths["/api/v1/auth/local/login"]={post:{summary:"Native local sign-in; opt-in API-owned credentials, throttling and durable sessions",requestBody:{required:true,content:{"application/json":{schema:z.toJSONSchema(localBrowserLoginSchema)}}},responses:{200:{description:"Secure HttpOnly SameSite=Lax cookie issued; no-store"},...localAuthResponses}}};
  paths["/api/v1/auth/oathweave/session"]={post:{summary:"Exchange an independently verified, explicitly linked Oathweave resource identity for a short-lived API-owned browser cookie; validates online revocation on every use",security:[{bearerAuth:[]}],responses:{200:{description:"Secure HttpOnly SameSite=Lax cookie; encrypted credential remains server-owned"},...localAuthResponses}}};
  paths["/api/v1/auth/local/session"]={get:{summary:"Verify API-owned local or Oathweave browser session and current revocation state",security:[{browserCookie:[]}],responses:{200:{description:"Current local identity",content:{"application/json":{schema:z.toJSONSchema(localBrowserProfileSchema)}}},...localAuthResponses}}};
  paths["/api/v1/auth/local/logout"]={post:{summary:"Durably revoke current session or its local account/linked identity sessions before clearing cookie",security:[{browserCookie:[]}],parameters:[{name:"all",in:"query",schema:{type:"boolean"}}],responses:{200:{description:"Revoked and cookie cleared"},...localAuthResponses}}};
  return {
    openapi: "3.1.0",
    info: {
      title: "Cindertrace API",
      version: "0.2.1",
      description:
        "Standalone security cases, evidence, investigation, and exact-plan response approvals. Ingestion requires source-bound HMAC headers. Agent credentials never approve containment.",
    },
    components: {
      securitySchemes: {
        bearerAuth: { type: "http", scheme: "bearer" },
        browserCookie:{type:"apiKey",in:"cookie",name:"cindertrace_session",description:"Native API-owned local browser session; server checks durable revocation and exact Origin for mutations."},
        collectorSignature: {
          type: "apiKey",
          in: "header",
          name: "x-security-signature",
          description:
            "HMAC over collector ID, timestamp, nonce and exact body; all four x-security-* headers are required.",
        },
      },
    },
    paths,
  };
}
