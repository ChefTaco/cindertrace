import {
  EmptyState,
  FusionHeader,
} from "@/components/security-fusion/fusion-ui";
import { fusionFetch, type FusionEntity } from "@/lib/security-fusion";

export const dynamic = "force-dynamic";

export default async function EntitiesPage(): Promise<React.ReactElement> {
  const entities = await fusionFetch<FusionEntity[]>("entities");
  return (
    <main className="p-5 lg:p-7">
      <FusionHeader
        eyebrow="Identity graph"
        title="Entities"
        copy="Canonical users, hosts, services, addresses, and domains connect observations across source-specific aliases."
      />
      {!entities?.length ? (
        <EmptyState>No entities have been resolved.</EmptyState>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {entities.map((entity) => (
            <div key={entity.id} className="border border-border/60 p-4">
              <p className="font-mono text-[9px] uppercase tracking-widest text-primary">
                {entity.type}
              </p>
              <p className="mt-2 text-sm text-text">{entity.label}</p>
              <p className="mt-2 truncate font-mono text-[10px] text-text-muted">
                {entity.canonical}
              </p>
            </div>
          ))}
        </div>
      )}
    </main>
  );
}
