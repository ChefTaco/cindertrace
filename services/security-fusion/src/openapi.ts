import { z } from "zod";
import {
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
      route.path === "/ingest/events"
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
  return {
    openapi: "3.1.0",
    info: {
      title: "Cindertrace API",
      version: "0.1.0",
      description:
        "Standalone security cases, evidence, investigation, and exact-plan response approvals. Ingestion requires source-bound HMAC headers. Agent credentials never approve containment.",
    },
    components: {
      securitySchemes: {
        bearerAuth: { type: "http", scheme: "bearer" },
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
