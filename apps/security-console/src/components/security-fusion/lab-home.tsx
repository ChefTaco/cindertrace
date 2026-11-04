'use client';
import type { LabStatus } from '@cindertrace/contracts';
import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';

export async function labPost(path: string, body: unknown = {}): Promise<Record<string, unknown>> {
  const response = await fetch(`/api/proxy/security-fusion/${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error?.message ?? payload.error ?? 'Request failed');
  return payload.data as Record<string, unknown>;
}
export const labButton = 'border border-primary/50 px-4 py-2 text-xs text-primary hover:bg-primary/10 focus-visible:outline-2 focus-visible:outline-primary disabled:opacity-40';
export function LabHome({canAdmin, runs}: Pick<LabStatus, 'canAdmin' | 'runs'>) {
  const router = useRouter();
  const [busy, setBusy] = useState(false), [message, setMessage] = useState('');
  const active = runs.find(x => x.status === 'active');
  async function start() {
    setBusy(true);
    try { const run = await labPost('lab/runs'); router.push(`/security-fusion/cases/${run.caseId}`); }
    catch (error) { setMessage(error instanceof Error ? error.message : 'Could not start lab'); setBusy(false); }
  }
  return <div className="space-y-6">
    <section className="border-l-2 border-primary bg-surface p-6">
      <p className="text-xs uppercase tracking-widest text-primary">One case · three evidence releases</p>
      <h2 className="mt-3 text-xl text-text">What would change your mind?</h2>
      <p className="mt-3 max-w-2xl text-sm leading-6 text-text-muted">Investigate an application login finding. Save what you believe, cite what supports it, then reveal the next evidence. At the end, compare your assertions and containment choices across revisions.</p>
      <p className="my-4 text-xs text-warning">Synthetic evidence only. Containment decisions are simulated and require human approval.</p>
      {active ? <Link className={labButton} href={`/security-fusion/cases/${active.caseId}`}>Resume stage {active.stage}</Link> : canAdmin ? <button className={labButton} disabled={busy} onClick={() => void start()}>Start investigation</button> : <p className="text-sm text-text-muted">An administrator can start a disposable investigation.</p>}
      {message && <p role="alert" className="mt-3 text-sm text-warning">{message}</p>}
    </section>
    {runs.length > 0 && <section><h2 className="mb-3 text-xs uppercase tracking-widest text-text-muted">Run history</h2><ul className="space-y-2">{runs.map((run, i) => <li key={run.id}><Link className="flex flex-wrap justify-between gap-2 border border-border p-4 text-sm text-text hover:border-primary" href={`/security-fusion/cases/${run.caseId}`}><span>Investigation {runs.length - i}</span><span>{run.status} · stage {run.stage}/3</span></Link></li>)}</ul></section>}
  </div>;
}
