// Product-owned public browser API. Apache-2.0; no persistence or server imports.
import { z } from 'zod';
import { securityFusionContainmentPreviewSchema, securityFusionInvestigationDraftSchema } from './index.js';
import { labStatusSchema,labRunSchema,labComparisonSchema,labTransitionSchema,labDecisionSchema } from './lab.js';
const id=z.string().min(1),text=z.string(),time=z.string(),json=z.record(z.string(),z.json());
const severity=z.enum(['info','low','medium','high','critical']);
export const fusionCaseSchema=z.object({id,title:text,severity,status:text,confidence:z.number(),summary:text,firstSeenAt:time,lastSeenAt:time,recommendedInvestigation:z.array(text),evidenceSteps:z.array(text)});
export const fusionEventSchema=z.object({id,eventId:text,source:text,kind:text,observedAt:time,severity,confidence:z.number(),summary:text,integritySha256:text,confidenceContribution:z.number().optional(),attributes:json.optional()});
export const fusionEntitySchema=z.object({id,type:text,canonical:text,label:text,lastSeenAt:time});
export const fusionSourceSchema=z.object({source:text,status:text,lastEventAt:time.nullish(),lastSuccessAt:time.nullish(),lastError:text.nullish()});
export const fusionCollectorSchema=z.object({id,displayName:text,allowedSources:z.array(text),schemaVersion:text,dataClassification:text,status:text,cursorHealth:text,lastReceiptAt:time.nullish(),lastSuccessAt:time.nullish(),revokedAt:time.nullish()});
export const fusionEvidenceSchema=z.object({id,sourceLocator:text.optional(),sha256:text,preservedAt:time,mediaType:text});
const investigation=z.object({id,revision:z.number().int(),draft:securityFusionInvestigationDraftSchema,authorId:text,createdAt:time});
const action=z.object({id,kind:text,status:text,createdAt:time,previewSha256:text.optional()});
export const fusionCaseDetailSchema=z.object({case:fusionCaseSchema,events:z.array(fusionEventSchema),entities:z.array(fusionEntitySchema),evidence:z.array(fusionEvidenceSchema),investigations:z.array(investigation),actions:z.array(action),labRunId:text.nullable(),responseAvailable:z.boolean(),canApprove:z.boolean(),approvalMode:z.enum(['console','external'])});
export const fusionOverviewSchema=z.object({generatedAt:time,openCases:z.array(fusionCaseSchema),sources:z.array(fusionSourceSchema),bySeverity:z.array(z.object({severity:text,_count:z.object({id:z.number().int()})}))});
export const fusionPoliciesSchema=z.object({eventRetentionDays:z.number(),preservedEvidenceDays:z.number(),caseArchiveDays:z.number(),archiveGraceDays:z.number(),deletionReceiptDays:z.number(),perCaseCeilings:z.object({events:z.number(),entities:z.number(),relationships:z.number(),preservedEvidence:z.number(),preservedEvidenceBytes:z.number()}),approvalTtlMinutes:z.number(),allowedActions:z.array(text),deniedActions:z.array(text),isolation:z.object({defaultMinutes:z.number(),maximumMinutes:z.number(),defaultPolicy:text})});
export const fusionAuditSchema=z.object({verification:z.object({state:text,legacyEntries:z.number(),totalEntries:z.number()}),events:z.array(z.object({id,timestamp:time,action:text,actorId:text,targetId:text,verificationState:text})),total:z.number()});
export const securityAdminDecisionSchema=z.object({planSha256:z.string().regex(/^[a-f0-9]{64}$/),previewSha256:z.string().regex(/^[a-f0-9]{64}$/),confirmed:z.literal(true)}).strict();
const actionView=z.object({id,status:text,previewSha256:text.optional(),preview:json.optional(),plan:json.optional(),approvalExpiresAt:time.optional(),caseId:text.optional(),commandId:text.nullish()});
const decision=z.object({id,actionId:id,executionId:text.nullable()}).loose();
export const securityBrowserContractVersion=1;
export const securityBrowserRoutes:{method:string;path:string;response:z.ZodType;request?:z.ZodType}[]=[
 {method:'GET',path:'/overview',response:fusionOverviewSchema},
 {method:'GET',path:'/cases',response:z.array(fusionCaseSchema)},
 {method:'GET',path:'/cases/{id}',response:fusionCaseDetailSchema},
 {method:'GET',path:'/events',response:z.array(fusionEventSchema)},
 {method:'GET',path:'/entities',response:z.array(fusionEntitySchema)},
 {method:'GET',path:'/sources',response:z.array(fusionSourceSchema)},
 {method:'GET',path:'/source-registry',response:z.array(fusionCollectorSchema)},
 {method:'GET',path:'/evidence',response:z.array(fusionEvidenceSchema)},
 {method:'GET',path:'/policies',response:fusionPoliciesSchema},
 {method:'GET',path:'/audit',response:fusionAuditSchema},
 {method:'POST',path:'/cases/{id}/investigations',request:securityFusionInvestigationDraftSchema,response:investigation},
 {method:'POST',path:'/cases/{id}/evidence/{eventId}/preserve',response:fusionEvidenceSchema},
 {method:'POST',path:'/cases/{id}/actions/preview',request:securityFusionContainmentPreviewSchema,response:actionView},
 {method:'GET',path:'/approval-plans/{id}',response:json},
 ...['request','cancel','release'].map(suffix=>({method:'POST',path:'/actions/{id}/'+suffix,response:actionView})),
 ...['approve','reject'].map(suffix=>({method:'POST',path:'/actions/{id}/'+suffix,request:securityAdminDecisionSchema,response:decision})),
 {method:'GET',path:'/lab',response:labStatusSchema},
 {method:'GET',path:'/lab/runs/{id}',response:labRunSchema},
 {method:'GET',path:'/lab/runs/{id}/comparison',response:labComparisonSchema},
 {method:'POST',path:'/lab/runs',request:z.object({}).strict(),response:z.object({id,caseId:id})},
 {method:'POST',path:'/lab/runs/{id}/restart',request:z.object({}).strict(),response:z.object({id,caseId:id})},
 ...['advance','complete'].map(suffix=>({method:'POST',path:'/lab/runs/{id}/'+suffix,request:labTransitionSchema,response:z.object({id,stage:z.number().int(),status:text})})),
 {method:'POST',path:'/lab/runs/{id}/simulations/{simulationId}/decision',request:labDecisionSchema,response:z.object({id,status:text,simulated:z.literal(true)})},
];
export function securityBrowserRoute(path:string,method='GET') {
 if(!path.startsWith('security-fusion/') || /[\\#]/u.test(path) || path.includes('..'))throw Error('Invalid security browser path');
 const pathname='/'+path.slice('security-fusion/'.length).split('?')[0];
 const route=securityBrowserRoutes.find(value=>value.method===method.toUpperCase()&&new RegExp('^'+value.path.replace(/\{[^}]+\}/gu,'[^/]+')+'$','u').test(pathname));
 if(!route)throw Error('Security browser route has no released contract');return route;
}
export function securityBrowserResponseSchema(path:string,method='GET') {return z.object({success:z.literal(true),data:securityBrowserRoute(path,method).response});}
export type FusionCase=z.infer<typeof fusionCaseSchema>;
export type FusionEvent=z.infer<typeof fusionEventSchema>;
export type FusionEntity=z.infer<typeof fusionEntitySchema>;
export type FusionSource=z.infer<typeof fusionSourceSchema>;
export type FusionCollector=z.infer<typeof fusionCollectorSchema>;
