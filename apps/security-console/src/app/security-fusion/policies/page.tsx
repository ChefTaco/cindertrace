import { FusionHeader } from "@/components/security-fusion/fusion-ui";
import { fusionFetch } from "@/lib/security-fusion";

export const dynamic = "force-dynamic";

interface Policies {
  eventRetentionDays: number;
  preservedEvidenceDays: number;
  caseArchiveDays: number;
  archiveGraceDays: number;
  deletionReceiptDays: number;
  perCaseCeilings: {
    events: number;
    entities: number;
    relationships: number;
    preservedEvidence: number;
    preservedEvidenceBytes: number;
  };
  approvalTtlMinutes: number;
  allowedActions: string[];
  deniedActions: string[];
  isolation: {
    defaultMinutes: number;
    maximumMinutes: number;
    defaultPolicy: string;
  };
}
export default async function PoliciesPage(): Promise<React.ReactElement> {
  const policy = await fusionFetch<Policies>("policies");
  const evidenceMiB = Math.round(
    (policy?.perCaseCeilings.preservedEvidenceBytes ?? 8388608) / 1048576,
  );
  return (
    <main className="p-5 lg:p-7">
      <FusionHeader
        eyebrow="Hard safety boundaries"
        title="Policies"
        copy="Policy is descriptive here; expanding executable authority requires a code and deployment review."
      />
      <div className="grid gap-4 lg:grid-cols-3">
        <section className="border border-border/60 p-5">
          <h2 className="text-sm font-semibold text-text">
            Retention lifecycle
          </h2>
          <dl className="mt-4 grid grid-cols-2 gap-3 text-xs text-text-muted">
            <dt>Normalized events</dt>
            <dd>{policy?.eventRetentionDays ?? 90} days</dd>
            <dt>Preserved evidence</dt>
            <dd>{policy?.preservedEvidenceDays ?? 365} days</dd>
            <dt>Case archive</dt>
            <dd>{policy?.caseArchiveDays ?? 365} days</dd>
            <dt>Archive grace</dt>
            <dd>{policy?.archiveGraceDays ?? 30} days</dd>
            <dt>Deletion receipts</dt>
            <dd>{policy?.deletionReceiptDays ?? 2555} days</dd>
          </dl>
        </section>
        <section className="border border-border/60 p-5">
          <h2 className="text-sm font-semibold text-text">Per-case ceilings</h2>
          <dl className="mt-4 grid grid-cols-2 gap-3 text-xs text-text-muted">
            <dt>Correlated events</dt>
            <dd>{policy?.perCaseCeilings.events ?? 1000}</dd>
            <dt>Entities</dt>
            <dd>{policy?.perCaseCeilings.entities ?? 250}</dd>
            <dt>Relationships</dt>
            <dd>{policy?.perCaseCeilings.relationships ?? 50}</dd>
            <dt>Preserved artifacts</dt>
            <dd>{policy?.perCaseCeilings.preservedEvidence ?? 100}</dd>
            <dt>Artifact storage</dt>
            <dd>{evidenceMiB} MiB</dd>
            <dt>Approval token</dt>
            <dd>{policy?.approvalTtlMinutes ?? 10} minutes</dd>
          </dl>
        </section>
        <section className="border border-border/60 p-5">
          <h2 className="text-sm font-semibold text-text">
            Containment boundary
          </h2>
          <p className="mt-4 font-mono text-[10px] uppercase tracking-wider text-success">
            Available
          </p>
          <p className="mt-2 text-xs text-text-muted">
            {policy?.allowedActions.join(" · ") ??
              "service restart · host isolation"}
          </p>
          <p className="mt-5 font-mono text-[10px] uppercase tracking-wider text-danger">
            Unavailable
          </p>
          <p className="mt-2 text-xs text-text-muted">
            {policy?.deniedActions.join(" · ") ??
              "credential rotation · permanent block · arbitrary command"}
          </p>
          <p className="mt-5 text-xs text-text-muted">
            Isolation ceiling: {policy?.isolation.maximumMinutes ?? 30} minutes.
          </p>
        </section>
      </div>
    </main>
  );
}
