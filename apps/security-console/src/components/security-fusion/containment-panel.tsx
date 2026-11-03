"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";

interface ExistingAction {
  id: string;
  kind: string;
  status: string;
  previewSha256?: string;
}

async function post(
  path: string,
  body?: unknown,
): Promise<Record<string, unknown>> {
  const response = await fetch(`/api/proxy/security-fusion/${path}`, {
    method: "POST",
    headers:
      body === undefined ? undefined : { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const payload = (await response.json()) as Record<string, unknown>;
  if (!response.ok) {
    const error = payload["error"] as Record<string, unknown> | undefined;
    throw new Error(
      String(
        error?.["message"] ?? payload["error"] ?? `HTTP ${response.status}`,
      ),
    );
  }
  return payload["data"] as Record<string, unknown>;
}

export function ContainmentPanel({
  caseId,
  actions, available = false, canApprove = false, approvalMode = "console",
}: {
  caseId: string;
  actions: ExistingAction[];
  available?: boolean; canApprove?: boolean; approvalMode?: "console" | "external";
}): React.ReactElement {
  const router = useRouter();
  useEffect(() => {
    if (!actions.some(action => ['dispatch_pending','executing','verifying','release_pending','releasing'].includes(action.status))) return;
    const timer = setInterval(() => router.refresh(), 3000);
    return () => clearInterval(timer);
  }, [actions, router]);
  const [nodeId, setNodeId] = useState("");
  const [serviceName, setServiceName] = useState("");
  const [kind, setKind] = useState<"service_restart" | "host_isolation">(
    "service_restart",
  );
  const [rationale, setRationale] = useState("");
  const [draft, setDraft] = useState<Record<string, unknown> | null>(null);
  const [message, setMessage] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);

  async function run(label: string, fn: () => Promise<void>): Promise<void> {
    setBusy(true);
    setConfirmed(false);
    setMessage("");
    try {
      await fn();
      setMessage(label);
      router.refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Request failed");
    } finally {
      setBusy(false);
    }
  }

  if (!available) return <section className="border border-border/60 p-4"><h2 className="text-xs uppercase">Response</h2><p className="mt-3 text-xs text-text-muted">Magnus response is not configured.</p></section>;
  return (
    <section className="border border-border/60 p-4">
      <h2 className="font-mono text-[10px] uppercase tracking-widest text-primary">
        Containment
      </h2>
      <p className="mt-3 text-xs leading-5 text-text-muted">
        Preview creates no effect. An administrator must explicitly approve the exact response plan before it can execute. Approval expires after ten minutes.
      </p>
      <div className="mt-4 grid gap-2">
        <select
          value={kind}
          onChange={(event) => setKind(event.target.value as typeof kind)}
          className="border border-border bg-bg p-2 text-xs text-text"
        >
          <option value="service_restart">Service restart</option>
          <option value="host_isolation">Temporary host isolation</option>
        </select>
        <input
          value={nodeId}
          onChange={(event) => setNodeId(event.target.value)}
          placeholder="Magnus node ID"
          className="border border-border bg-bg p-2 text-xs text-text"
        />
        {kind === "service_restart" && (
          <input
            value={serviceName}
            onChange={(event) => setServiceName(event.target.value)}
            placeholder="Allowlisted active unit.service"
            className="border border-border bg-bg p-2 text-xs text-text"
          />
        )}
        <textarea
          value={rationale}
          onChange={(event) => setRationale(event.target.value)}
          placeholder="Rationale (minimum 10 characters)"
          className="min-h-20 border border-border bg-bg p-2 text-xs text-text"
        />
        <button
          disabled={busy}
          onClick={() =>
            void run("Preview created", async () =>
              setDraft(
                await post(`cases/${caseId}/actions/preview`, {
                  nodeId,
                  kind,
                  serviceName:
                    kind === "service_restart" ? serviceName : undefined,
                  isolationMinutes: kind === "host_isolation" ? 15 : undefined,
                  rationale,
                }),
              ),
            )
          }
          className="border border-primary/40 px-3 py-2 text-[10px] uppercase tracking-wider text-primary disabled:opacity-40"
        >
          Preview
        </button>
      </div>
      {draft && (
        <div className="mt-4 border border-primary/20 bg-primary/[.03] p-3">
          <p className="font-mono text-[9px] text-text-muted">
            SHA-256 {String(draft["previewSha256"])}
          </p>
          <pre className="mt-2 whitespace-pre-wrap text-xs text-text-muted">{JSON.stringify(draft["preview"], null, 2)}</pre>
          <button
            disabled={busy}
            onClick={() =>
              void run("Approval requested", async () => {
                const result = await post(
                  `actions/${String(draft["id"])}/request`,
                );
                setDraft(result);
              })
            }
            className="mt-3 border border-primary/40 px-3 py-2 text-[10px] uppercase tracking-wider text-primary"
          >
            Request approval
          </button>
        </div>
      )}
      {draft?.["plan"] != null && <div className="mt-4 space-y-3 border border-warning/40 p-3">
        <h3 className="text-xs uppercase text-warning">Approve exact response</h3>
        <pre className="whitespace-pre-wrap break-all text-xs">{JSON.stringify(draft["plan"], null, 2)}</pre>
        {approvalMode === "external" ? <p className="text-xs">This installation requires its signed external approval channel.</p> : canApprove && <>
          <label className="flex gap-2 text-xs"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} />I reviewed the target, effect, risks, and rollback for this exact plan.</label>
          <button disabled={busy || !confirmed} className="border border-warning px-3 py-2 text-xs disabled:opacity-40" onClick={() => void run("Decision recorded", async () => {
            const plan = draft["plan"] as Record<string, unknown>;
            await post(`actions/${String(draft["id"])}/approve`, { confirmed: true, planSha256: plan["plan_sha256"], previewSha256: draft["previewSha256"] }); setDraft(null);
          })}>Approve and execute</button>
          <button disabled={busy} className="ml-2 border border-border px-3 py-2 text-xs" onClick={() => void run("Response rejected", async () => {
            const plan = draft["plan"] as Record<string, unknown>;
            await post(`actions/${String(draft["id"])}/reject`, { confirmed: true, planSha256: plan["plan_sha256"], previewSha256: draft["previewSha256"] }); setDraft(null);
          })}>Reject</button>
        </>}
      </div>}
      {actions
        .filter(
          (action) =>
            action.kind === "host_isolation" &&
            ["executing", "succeeded", "unknown"].includes(action.status),
        )
        .map((action) => (
          <button
            key={action.id}
            disabled={busy}
            onClick={() =>
              void run("Emergency release queued", async () => {
                await post(`actions/${action.id}/release`);
              })
            }
            className="mt-3 block border border-danger/50 px-3 py-2 text-[10px] uppercase tracking-wider text-danger"
          >
            Release isolation {action.id.slice(-6)}
          </button>
        ))}
      {actions
        .filter((action) =>
          ["previewed", "pending_approval"].includes(action.status),
        )
        .map((action) => (
          <div key={action.id} className="mt-3 flex gap-2">
            <button disabled={busy} onClick={() => void run("Response ready for review; no action executed", async () => {
              if (action.status === "previewed") setDraft(await post(`actions/${action.id}/request`));
              else {
                const response = await fetch(`/api/proxy/security-fusion/approval-plans/${encodeURIComponent(`containment:${action.id}`)}`);
                if (!response.ok) throw new Error("Response plan is unavailable or expired");
                const result = await response.json() as { data: unknown };
                setDraft({ id: action.id, previewSha256: action.previewSha256, plan: result.data });
              }
            })} className="border border-primary/40 px-3 py-2 text-[10px] uppercase tracking-wider text-primary">
              Review response {action.id.slice(-6)}
            </button>
            <button
              disabled={busy}
              onClick={() =>
                void run("Pending action cancelled", async () => {
                  await post(`actions/${action.id}/cancel`);
                })
              }
              className="border border-border px-3 py-2 text-[10px] uppercase tracking-wider text-text-muted"
            >
              Cancel {action.id.slice(-6)}
            </button>
          </div>
        ))}
      {actions.length > 0 && <div className="mt-4 space-y-2" aria-label="Action history">
        {actions.map(action => <div key={action.id} className="border border-border/60 p-2 text-xs text-text-muted">
          <p>{action.kind.replaceAll('_', ' ')} · {action.status.replaceAll('_', ' ')} · {action.id.slice(-6)}</p>
          {action.status === 'unknown' && <p className="mt-2 text-warning">Execution outcome unknown. Verify the target before creating another action.</p>}
        </div>)}
      </div>}
      {message && <p className="mt-3 text-[10px] text-text-muted">{message}</p>}
    </section>
  );
}
