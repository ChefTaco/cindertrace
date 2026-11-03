import { sourceLabel } from "@/lib/security-fusion";
import Link from 'next/link';
import { ScanSearch } from 'lucide-react';
import type { FusionCase, FusionCollector, FusionEvent, FusionSource } from '@/lib/security-fusion';
import { severityClass } from '@/lib/security-fusion';
import { cn } from '@/lib/cn';
import { PageHeader } from '@/components/ui/page-header';
import { EmptyState as UiEmptyState } from '@/components/ui/empty-state';
import { MeterBar } from '@/components/ui/meter-bar';
import { StatusDot } from '@/components/ui/status-dot';
import { Badge } from '@/components/ui/badge';

// Shared verbatim between apps/dashboard and apps/security-console (see scripts/check-ui-parity.mjs).

export function FusionHeader({ eyebrow, title, copy }: { eyebrow: string; title: string; copy: string }): React.ReactElement {
  return (
    <header className="mb-6 border-b border-border/50 pb-5">
      <PageHeader eyebrow={eyebrow} title={title} description={copy} tone="accent" />
    </header>
  );
}

export function EmptyState({ children }: { children: React.ReactNode }): React.ReactElement {
  return <UiEmptyState icon={<ScanSearch className="h-5 w-5" />} title="Nothing to show" description={children} />;
}

const SEVERITY_BAR: Record<FusionCase['severity'], string> = {
  info: 'shadow-[inset_2px_0_0_var(--color-border-strong)]',
  low: 'shadow-[inset_2px_0_0_var(--color-primary)]',
  medium: 'shadow-[inset_2px_0_0_var(--color-warning)]',
  high: 'shadow-[inset_3px_0_0_var(--color-accent)]',
  critical: 'shadow-[inset_3px_0_0_var(--color-danger)] bg-danger/[.04]',
};

export function CaseTable({ cases }: { cases: FusionCase[] }): React.ReactElement {
  if (!cases.length)
    return (
      <EmptyState>
        No correlated cases yet. Source observations remain quiet until a deterministic rule has enough evidence.
      </EmptyState>
    );
  return (
    <div className="overflow-hidden rounded-panel border border-border/60 bg-surface">
      {cases.map((item) => (
        <Link
          key={item.id}
          href={`/security-fusion/cases/${item.id}`}
          prefetch={false}
          className={cn(
            'grid items-center gap-2 border-b border-border/40 p-4 transition-colors last:border-0 hover:bg-accent/[.05] md:grid-cols-[110px_1fr_140px_110px]',
            SEVERITY_BAR[item.severity],
          )}
        >
          <span
            className={cn(
              'inline-flex w-fit items-center gap-1.5 rounded-chip border px-2 py-1 text-[10px] font-bold uppercase tracking-wider',
              severityClass[item.severity],
            )}
          >
            {item.severity === 'critical' && <StatusDot status="CRITICAL" size="xs" />}
            {item.severity}
          </span>
          <span className="min-w-0">
            <strong className="block truncate text-sm text-text">{item.title}</strong>
            <span className="mt-1 line-clamp-1 block text-xs text-text-muted">{item.summary}</span>
          </span>
          <MeterBar
            value={item.confidence * 100}
            tone={item.confidence >= 0.8 ? 'accent' : item.confidence >= 0.5 ? 'warning' : 'muted'}
            label={`${item.title} confidence`}
            valueLabel={`${Math.round(item.confidence * 100)}% conf.`}
            showValue
            className="[&>span]:w-16"
          />
          <span className="text-right text-[10px] uppercase tracking-wider text-primary">{item.status}</span>
        </Link>
      ))}
    </div>
  );
}

const laneColor: Record<string, string> = {
  unifi_dns: 'bg-primary text-primary',
  unifi_ids: 'bg-accent text-accent',
  netflow: 'bg-info text-info',
  wazuh: 'bg-warning text-warning',
  tailscale: 'bg-primary-hover text-primary-hover',
  magnus: 'bg-success text-success',
  hive: 'bg-accent-hover text-accent-hover',
  chattermost: 'bg-danger text-danger',
};

export function EvidenceBraid({ events }: { events: FusionEvent[] }): React.ReactElement {
  if (!events.length) return <EmptyState>No event lanes are attached to this case.</EmptyState>;
  return (
    <div className="grid-bg relative overflow-hidden rounded-panel border border-border/60 bg-bg/50 p-4">
      <div className="absolute bottom-0 left-1/2 top-0 w-px bg-gradient-to-b from-transparent via-accent/40 to-accent shadow-[0_0_8px_var(--color-accent)]" />
      <div className="space-y-3">
        {events.map((event, index) => (
          <div key={event.id} className={`relative grid grid-cols-[1fr_28px_1fr] items-center ${index % 2 ? '' : 'text-right'}`}>
            <div className={cn('rounded-chip border border-border/50 bg-surface/80 px-3 py-2', index % 2 ? 'col-start-3' : 'col-start-1')}>
              <p className="num text-[9px] uppercase tracking-wider text-text-muted">
                {sourceLabel(event.source)} · {new Date(event.observedAt).toLocaleString()}
              </p>
              <p className="mt-1 text-xs text-text">{event.summary}</p>
              <p className="num mt-1 text-[9px] text-accent/80">
                {Math.round((event.confidenceContribution ?? event.confidence) * 100)}% confidence contribution
              </p>
            </div>
            <span className="relative col-start-2 row-start-1 mx-auto flex h-3 w-3 items-center justify-center">
              <span className={cn('absolute inset-0 rounded-full opacity-40 animate-halo', laneColor[event.source] ?? 'bg-primary')} />
              <span className={cn('relative h-2.5 w-2.5 rounded-full shadow-[0_0_9px_currentColor]', laneColor[event.source] ?? 'bg-primary text-primary')} />
            </span>
          </div>
        ))}
      </div>
      <div className="relative mx-auto mt-5 w-fit rounded-panel border border-accent/60 bg-bg px-4 py-2 text-center shadow-[0_0_24px_var(--color-glow-accent)]">
        <p className="text-[9px] font-bold uppercase tracking-[.24em] text-accent glow-text-accent">Correlated case</p>
      </div>
    </div>
  );
}

const STALE_MS = 15 * 60 * 1000;

export function SourceGrid({ sources }: { sources: FusionSource[] }): React.ReactElement {
  return (
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
      {sources.map((source) => {
        const healthy = source.status === 'healthy';
        const lastSuccess = source.lastSuccessAt ? Date.parse(source.lastSuccessAt) : null;
        const stale = lastSuccess === null || Date.now() - lastSuccess > STALE_MS;
        return (
          <div
            key={source.source}
            className={cn(
              'panel-corners rounded-panel border bg-surface p-4 transition-colors',
              healthy ? 'border-border/60 hover:border-success/40' : 'border-warning/30 [--panel-corner-color:var(--color-warning)]',
            )}
          >
            <div className="flex items-center justify-between">
              <strong className="text-xs uppercase tracking-wider text-text">{sourceLabel(source.source)}</strong>
              <StatusDot status={healthy ? 'HEALTHY' : source.status === 'error' ? 'ERROR' : 'DEGRADED'} label={source.status} />
            </div>
            <p className={cn('mt-3 text-[10px] uppercase tracking-wider', healthy ? 'text-success' : 'text-warning')}>{source.status}</p>
            <p className={cn('num mt-1 text-[10px]', stale ? 'text-warning' : 'text-text-muted')}>
              Last successful poll: {source.lastSuccessAt ? new Date(source.lastSuccessAt).toLocaleString() : 'Never'}
            </p>
            <p className="num mt-1 text-[10px] text-text-muted">
              Last event: {source.lastEventAt ? new Date(source.lastEventAt).toLocaleString() : 'No evidence received'}
            </p>
            {source.lastError && <p className="mt-2 line-clamp-2 text-[10px] text-danger">{source.lastError}</p>}
          </div>
        );
      })}
    </div>
  );
}

export function CollectorRegistry({ collectors }: { collectors: FusionCollector[] }): React.ReactElement {
  if (!collectors.length) return <EmptyState>No collector identity has completed an authenticated receipt.</EmptyState>;
  return (
    <div className="max-h-[70vh] overflow-auto rounded-panel border border-border/60 bg-surface">
      <table className="w-full min-w-[760px] text-left text-xs">
        <thead className="sticky top-0 border-b border-accent/30 bg-surface/95 text-[9px] uppercase tracking-wider text-text-muted backdrop-blur-sm">
          <tr>
            <th className="p-3">Identity</th>
            <th className="p-3">Allowed sources</th>
            <th className="p-3">Schema</th>
            <th className="p-3">Classification</th>
            <th className="p-3">Cursor health</th>
            <th className="p-3">Last receipt</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border/40">
          {collectors.map((collector) => (
            <tr key={collector.id} className="transition-colors hover:bg-accent/[.04]">
              <td className="p-3">
                <strong className="flex items-center gap-2 text-text">
                  <StatusDot status={collector.revokedAt ? 'FAILED' : collector.status === 'active' ? 'ACTIVE' : collector.status} size="xs" />
                  {collector.displayName}
                </strong>
                <span className="num text-[9px] text-text-muted">
                  {collector.id} · {collector.status}
                </span>
              </td>
              <td className="p-3 text-text-muted">{collector.allowedSources.join(', ')}</td>
              <td className="num p-3 text-text-muted">{collector.schemaVersion}</td>
              <td className="p-3 uppercase text-text-muted">{collector.dataClassification}</td>
              <td className="p-3">
                <Badge
                  variant={collector.cursorHealth === 'healthy' || collector.cursorHealth === 'ok' ? 'success' : collector.cursorHealth === 'unknown' ? 'default' : 'warning'}
                  dot
                >
                  {collector.cursorHealth}
                </Badge>
              </td>
              <td className="num p-3 text-[10px] text-text-muted">
                {collector.lastReceiptAt ? new Date(collector.lastReceiptAt).toLocaleString() : 'Never'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
