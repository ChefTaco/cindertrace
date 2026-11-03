import {
  CaseTable,
  FusionHeader,
  SourceGrid,
} from "@/components/security-fusion/fusion-ui";
import {
  fusionFetch,
  type FusionCase,
  type FusionSource,
} from "@/lib/security-fusion";

export const dynamic = "force-dynamic";

interface Overview {
  generatedAt: string;
  openCases: FusionCase[];
  sources: FusionSource[];
  bySeverity: Array<{ severity: string; _count: { id: number } }>;
}

export default async function SecurityFusionOverview(): Promise<React.ReactElement> {
  const data = await fusionFetch<Overview>("overview");
  const counts = Object.fromEntries(
    (data?.bySeverity ?? []).map((row) => [row.severity, row._count.id]),
  );
  return (
    <main className="p-5 lg:p-7">
      <FusionHeader
        eyebrow="Security operations"
        title="Cindertrace"
        copy="Investigate security findings, connect related activity, and preserve evidence. Response requires explicit approval."
      />
      <section className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        {["critical", "high", "medium", "low"].map((severity) => (
          <div key={severity} className="border border-border/60 p-4">
            <p className="font-mono text-[10px] uppercase tracking-widest text-text-muted">
              {severity}
            </p>
            <p className="mt-2 text-3xl font-semibold text-text">
              {counts[severity] ?? 0}
            </p>
          </div>
        ))}
      </section>
      <h2 className="mb-3 text-xs font-bold uppercase tracking-[.2em] text-text-muted">
        Source posture
      </h2>
      <SourceGrid sources={data?.sources ?? []} />
      <h2 className="mb-3 mt-7 text-xs font-bold uppercase tracking-[.2em] text-text-muted">
        Active cases
      </h2>
      <CaseTable cases={data?.openCases ?? []} />
    </main>
  );
}
