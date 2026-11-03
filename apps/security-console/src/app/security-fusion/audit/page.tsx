import { securityFetch } from "@/lib/security-api";
import { FusionHeader } from "@/components/security-fusion/fusion-ui";
export default async function AuditPage({
  searchParams,
}: {
  searchParams: Promise<{ date?: string; page?: string }>;
}) {
  const params = await searchParams;
  const date = /^\d{4}-\d{2}-\d{2}$/.test(params.date ?? "")
    ? params.date!
    : new Date().toISOString().slice(0, 10);
  const page = Math.max(1, Math.min(100, Number(params.page) || 1));
  try {
    const { data } = await securityFetch<{
      data: {
        verification: {
          state: string;
          legacyEntries: number;
          totalEntries: number;
        };
        events: Array<{
          id: string;
          timestamp: string;
          action: string;
          actorId: string;
          targetId: string;
          verificationState: string;
        }>;
        total: number;
      };
    }>(`security-fusion/audit?date=${date}&page=${page}`);
    return (
      <main className="min-w-0 space-y-5 p-5 lg:p-7">
        <FusionHeader
          eyebrow="Decision and integrity trail"
          title="Audit"
          copy="Review security changes and verify the retained audit chain."
        />
        <form className="flex flex-wrap items-end gap-3">
          <label className="grid gap-2 text-xs text-text-muted">
            Audit date
            <input
              className="rounded border border-border bg-bg px-3 py-2 text-text"
              type="date"
              name="date"
              defaultValue={date}
            />
          </label>
          <button className="rounded border border-primary/40 px-3 py-2 text-xs text-primary hover:border-primary">
            Load day
          </button>
        </form>
        <p role="status">
          Chain: {data.verification.state} · {data.verification.totalEntries}{" "}
          records · {data.verification.legacyEntries} legacy entries with
          partial integrity
        </p>
        {data.verification.legacyEntries > 0 && (
          <p className="text-xs text-warning">
            Legacy signatures do not protect targets, details, actor type or IP
            address.
          </p>
        )}
        <div
          className="max-w-full overflow-x-auto border border-border"
          role="region"
          aria-label="Audit records"
          tabIndex={0}
        >
          <table className="w-full min-w-[680px] text-left text-xs [&_th]:px-3 [&_th]:py-3 [&_td]:px-3 [&_td]:py-3 [&_tr]:border-b [&_tr]:border-border/50">
            <caption className="sr-only">
              Security audit records for {date}
            </caption>
            <thead>
              <tr>
                {["Time", "Action", "Actor", "Target", "Integrity"].map(
                  (label) => (
                    <th scope="col" key={label}>
                      {label}
                    </th>
                  ),
                )}
              </tr>
            </thead>
            <tbody>
              {data.events.map((e) => (
                <tr key={e.id}>
                  <td className="whitespace-nowrap">
                    {new Date(e.timestamp).toLocaleString()}
                  </td>
                  <td>{e.action}</td>
                  <td>{e.actorId}</td>
                  <td>{e.targetId}</td>
                  <td>{e.verificationState}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {page > 1 && (
          <a href={`?date=${date}&page=${page - 1}`}>Newer records</a>
        )}{" "}
        {page * 100 < data.total && page < 100 && (
          <a href={`?date=${date}&page=${page + 1}`}>Older records</a>
        )}
      </main>
    );
  } catch {
    return (
      <main className="p-5 lg:p-7">
        <FusionHeader
          eyebrow="Decision and integrity trail"
          title="Audit"
          copy="Review security changes and verify the retained audit chain."
        />
        <p role="alert">
          Audit history is unavailable or access is denied. Integrity is
          unverified.
        </p>
      </main>
    );
  }
}
