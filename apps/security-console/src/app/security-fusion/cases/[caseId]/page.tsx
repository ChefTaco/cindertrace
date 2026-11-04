import { decodeRouteSegment } from "@/lib/route-segment";
import { LabCase } from "@/components/security-fusion/lab-case";
import type { LabRun, LabComparison } from "@cindertrace/contracts";
import {CaseWorkflow} from "@/components/security-fusion/case-workflow";
import {
  EvidenceBraid,
  FusionHeader,
} from "@/components/security-fusion/fusion-ui";
import {
  fusionFetch,
  type FusionCase,
  type FusionEntity,
  type FusionEvent,
} from "@/lib/security-fusion";
import { notFound } from "next/navigation";
import { ContainmentPanel } from "@/components/security-fusion/containment-panel";

interface CaseDetail {
  labRunId: string | null;
  responseAvailable: boolean;
  canApprove: boolean;
  approvalMode: "console" | "external";
  case: FusionCase;
  events: FusionEvent[];
  entities: FusionEntity[];
  activity: Array<{ id: string; kind: string; createdAt: string }>;
  evidence: Array<{
    id: string;
    sourceLocator: string;
    sha256: string;
    preservedAt: string;
  }>;
  investigations: Array<{
    id: string;
    revision: number;
    draft: {summary: string; hypotheses?: string[]; prioritizedChecks?: string[]; evidenceSteps?: string[]; proposedActions?: Array<{description:string;risk:string}>};
    authorId: string;
    createdAt: string;
  }>;
  actions: Array<{
    id: string;
    kind: string;
    status: string;
    createdAt: string;
  }>;
}

export default async function CasePage({
  params,
}: {
  params: Promise<{ caseId: string }>;
}): Promise<React.ReactElement> {
  const caseId = decodeRouteSegment((await params).caseId);
  const detail = await fusionFetch<CaseDetail>(
    `cases/${encodeURIComponent(caseId)}`,
  );
  if (!detail) notFound();
  const lab = detail.labRunId ? await fusionFetch<LabRun>(`lab/runs/${encodeURIComponent(detail.labRunId)}`) : null;
  const comparison = lab?.status === "completed" ? await fusionFetch<LabComparison>(`lab/runs/${encodeURIComponent(lab.id)}/comparison`) : null;
  return (
    <main className="p-5 lg:p-7">
      <FusionHeader
        eyebrow={`${detail.case.severity} · ${Math.round(detail.case.confidence * 100)}% ${lab ? "correlation confidence" : "confidence"}`}
        title={detail.case.title}
        copy={detail.case.summary}
      />
      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_340px]">
        <section className="min-w-0">
          <h2 className="mb-3 text-xs font-bold uppercase tracking-[.2em] text-text-muted">
            Evidence braid
          </h2>
          <EvidenceBraid events={detail.events} />
          {lab ? <>
            <LabCase key={`${lab.id}:${lab.stage}:${lab.latestRevision}:${lab.status}`} run={lab} comparison={comparison} />
            <CaseWorkflow caseId={detail.case.id} eventId={detail.events.at(-1)?.id} preserveOnly />
          </> : <CaseWorkflow caseId={detail.case.id} eventId={detail.events.at(-1)?.id} />}
          <section className="mt-6 space-y-3">
            <h2 className="text-xs uppercase tracking-widest text-text-muted">Saved investigations</h2>
            {detail.investigations.length===0?<p className="text-xs text-text-muted">No investigation drafts yet.</p>:detail.investigations.map(item=><article key={item.id} className="space-y-2 border border-border/60 p-4 text-sm text-text">
              <p className="font-mono text-xs text-primary">Revision {item.revision} · {item.authorId}</p>
              <p className="whitespace-pre-wrap">{item.draft.summary}</p>
              {[...(item.draft.hypotheses??[]),...(item.draft.prioritizedChecks??[]),...(item.draft.evidenceSteps??[])].map((text,i)=><p key={i} className="text-xs text-text-muted">{text}</p>)}
              {item.draft.proposedActions?.map((action,i)=><p key={i} className="text-xs text-text-muted">Proposed: {action.description} · {action.risk} risk · approval required</p>)}
            </article>)}
          </section>
          <section className="mt-6 space-y-2">
            <h2 className="text-xs uppercase tracking-widest text-text-muted">Preserved evidence</h2>
            {detail.evidence.map(item=><p key={item.id} className="break-all border border-border/60 p-3 font-mono text-xs text-text-muted">{item.sha256}</p>)}
          </section>
        </section>
        <aside className="min-w-0 space-y-4">
          <section className="border border-border/60 p-4">
            <h2 className="font-mono text-[10px] uppercase tracking-widest text-primary">
              Affected entities
            </h2>
            {detail.entities.map((entity) => (
              <p key={entity.id} className="mt-3 text-xs text-text">
                <span className="mr-2 text-text-muted">{entity.type}</span>
                {entity.label}
              </p>
            ))}
          </section>
          <section className="border border-border/60 p-4">
            <h2 className="font-mono text-[10px] uppercase tracking-widest text-primary">
              Recommended investigation
            </h2>
            <ol className="mt-3 list-decimal space-y-2 pl-4 text-xs leading-5 text-text-muted">
              {detail.case.recommendedInvestigation.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ol>
          </section>
          {!lab && <ContainmentPanel available={detail.responseAvailable} canApprove={detail.canApprove} approvalMode={detail.approvalMode} caseId={detail.case.id} actions={detail.actions} />}
        </aside>
      </div>
    </main>
  );
}
