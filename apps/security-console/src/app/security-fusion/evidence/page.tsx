import {
  EmptyState,
  FusionHeader,
} from "@/components/security-fusion/fusion-ui";
import { fusionFetch } from "@/lib/security-fusion";

export const dynamic = "force-dynamic";

interface Evidence {
  id: string;
  sourceLocator: string;
  sha256: string;
  preservedAt: string;
  mediaType: string;
}
export default async function EvidencePage(): Promise<React.ReactElement> {
  const evidence = await fusionFetch<Evidence[]>("evidence");
  return (
    <main className="p-5 lg:p-7">
      <FusionHeader
        eyebrow="Chain of custody"
        title="Evidence"
        copy="Preserved sanitized artifacts are content-addressed, SHA-256 verified, and retained for one year."
      />
      {!evidence?.length ? (
        <EmptyState>No evidence has been preserved.</EmptyState>
      ) : (
        <div className="space-y-2">
          {evidence.map((item) => (
            <div
              key={item.id}
              className="grid gap-2 border border-border/60 p-4 md:grid-cols-[1fr_160px_2fr]"
            >
              <span className="text-xs text-text">{item.sourceLocator}</span>
              <span className="font-mono text-[10px] text-text-muted">
                {item.mediaType}
              </span>
              <span className="truncate font-mono text-[10px] text-primary/70">
                {item.sha256}
              </span>
            </div>
          ))}
        </div>
      )}
    </main>
  );
}
