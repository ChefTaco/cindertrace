import type { LabStatus } from '@cindertrace/contracts';
import { notFound } from 'next/navigation';
import { FusionHeader } from '@/components/security-fusion/fusion-ui';
import { LabHome } from '@/components/security-fusion/lab-home';
import { fusionFetch } from '@/lib/security-fusion';
export const dynamic = 'force-dynamic';
export default async function LabPage() {
  const data = await fusionFetch<LabStatus>('lab');
  if (!data?.enabled) notFound();
  return <main className="p-5 lg:p-7"><FusionHeader eyebrow="Investigation practice" title="Evolving evidence lab" copy="A disposable case. A record of what you knew at each decision." /><LabHome canAdmin={data.canAdmin} runs={data.runs} /></main>;
}
