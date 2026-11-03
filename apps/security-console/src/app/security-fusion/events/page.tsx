import {
  EmptyState,
  FusionHeader,
} from "@/components/security-fusion/fusion-ui";
import {
  fusionFetch,
  severityClass,
  type FusionEvent,
} from "@/lib/security-fusion";

export const dynamic = "force-dynamic";

export default async function EventsPage(): Promise<React.ReactElement> {
  const events = await fusionFetch<FusionEvent[]>("events?limit=100");
  return (
    <main className="p-5 lg:p-7">
      <FusionHeader
        eyebrow="Normalized observations"
        title="Events"
        copy="Sanitized metadata only. DNS and flow records are summaries; Security Fusion captures no packets."
      />
      {!events?.length ? (
        <EmptyState>No normalized events received.</EmptyState>
      ) : (
        <div className="overflow-x-auto border border-border/60">
          <table className="w-full min-w-[760px] text-left text-xs">
            <thead className="bg-white/[.02] font-mono text-[9px] uppercase tracking-wider text-text-muted">
              <tr>
                <th className="p-3">Time</th>
                <th>Source</th>
                <th>Kind</th>
                <th>Summary</th>
                <th>Confidence</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event) => (
                <tr key={event.id} className="border-t border-border/40">
                  <td className="p-3 font-mono text-[10px] text-text-muted">
                    {new Date(event.observedAt).toLocaleString()}
                  </td>
                  <td className="uppercase text-primary">{event.source}</td>
                  <td>{event.kind}</td>
                  <td className="max-w-md py-3 text-text-muted">
                    {event.summary}
                  </td>
                  <td className={severityClass[event.severity]}>
                    {Math.round(event.confidence * 100)}%
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </main>
  );
}
