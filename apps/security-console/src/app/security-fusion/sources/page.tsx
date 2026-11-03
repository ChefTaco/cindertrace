import {
  CollectorRegistry,
  FusionHeader,
  SourceGrid,
} from "@/components/security-fusion/fusion-ui";
import {
  fusionFetch,
  type FusionCollector,
  type FusionSource,
} from "@/lib/security-fusion";

export const dynamic = "force-dynamic";

export default async function SourcesPage(): Promise<React.ReactElement> {
  const [sources, collectors] = await Promise.all([
    fusionFetch<FusionSource[]>("sources"),
    fusionFetch<FusionCollector[]>("source-registry"),
  ]);
  return (
    <main className="p-5 lg:p-7">
      <FusionHeader
        eyebrow="Eight required feeds"
        title="Sources"
        copy="Checkpointed, replay-safe ingestion posture for UniFi DNS, UniFi IDS/IPS, NetFlow/IPFIX, Wazuh, Tailscale, Magnus, Hive, and ChatterMost."
      />
      <SourceGrid sources={sources ?? []} />
      <section className="mt-7">
        <h2 className="mb-3 text-sm font-semibold text-text">
          Collector identity registry
        </h2>
        <CollectorRegistry collectors={collectors ?? []} />
      </section>
    </main>
  );
}
