import {
  CaseTable,
  FusionHeader,
} from "@/components/security-fusion/fusion-ui";
import { fusionFetch, type FusionCase } from "@/lib/security-fusion";

export const dynamic = "force-dynamic";

export default async function CasesPage(): Promise<React.ReactElement> {
  const cases = await fusionFetch<FusionCase[]>("cases");
  return (
    <main className="p-5 lg:p-7">
      <FusionHeader
        eyebrow="Correlated work queue"
        title="Cases"
        copy="Stable fingerprints merge related evidence, reopen resolved activity, and escalate material changes without alert-by-alert noise."
      />
      <CaseTable cases={cases ?? []} />
    </main>
  );
}
