import {isRehearsal} from "../config/rehearsal.js";
import { magnusRequest } from "@cindertrace/integrations";
import { responseConfigured } from "../config/runtime.js";
import { securityInventoryExportSchema } from "@cindertrace/contracts";
import { z } from "zod";
import { getDb } from "../db/index.js";
import { HttpError } from "../middleware/error-handler.js";
import { setMetricGauge } from "../routes/metrics.js";
export async function syncTargets(): Promise<void> {
  if(isRehearsal())return;
  const url = process.env["MAGNUS_INVENTORY_URL"];
  if (!url) return;
  const r = await fetch(url, {
    headers: {
      Authorization: `Bearer ${process.env["MAGNUS_INVENTORY_TOKEN"]}`,
    },
    signal: AbortSignal.timeout(10000),
    redirect: "error",
  });
  if (!r.ok) throw new Error(`inventory HTTP ${r.status}`);
  const raw = await r.text();
  if (Buffer.byteLength(raw) > 2_000_000)
    throw new Error("inventory too large");
  const { data } = securityInventoryExportSchema.parse(JSON.parse(raw));
  const syncedAt = new Date();
  for (const node of data) {
    if (new URL(node.baseUrl).protocol !== "https:")
      throw new Error("agent TLS required");
  }
  await getDb().$transaction(async (tx) => {
    for (const node of data)
      await tx.securityTarget.upsert({
        where: { id: node.id },
        create: { ...node, syncedAt },
        update: { ...node, syncedAt },
      });
    // Retain tombstones for emergency release, but make them ineligible for new actions.
    await tx.securityTarget.updateMany({
      where: { id: { notIn: data.map((x) => x.id) } },
      data: { syncedAt: new Date(0) },
    });
  });
  setMetricGauge("inventoryLastSuccessSeconds", Date.now() / 1000);
}
export async function agentHealth(
  baseUrl: string,
): Promise<{
  services: Array<{ name?: string; status?: string }>;
  wazuh?: { installed: boolean; serviceStatus: string };
  responseCapable?: boolean;
}> {
  if (!responseConfigured())
    throw new HttpError(
      503,
      "RESPONSE_UNCONFIGURED",
      "Magnus response is not configured",
    );
  const node = await getDb().securityTarget.findFirst({ where: { baseUrl } });
  if (!node)
    throw new HttpError(
      409,
      "TARGET_NOT_READY",
      "Target is not in the inventory",
    );
  const raw = await magnusRequest(
    `/targets/${encodeURIComponent(node.id)}/health`,
  );
  return z
    .object({
      data: z.object({
        responseCapable: z.boolean().optional(),
        services: z.array(
          z.object({
            name: z.string().optional(),
            status: z.string().optional(),
          }),
        ),
        wazuh: z
          .object({ installed: z.boolean(), serviceStatus: z.string() })
          .optional(),
      }),
    })
    .parse(raw).data;
}
export async function readyTarget(id: string, release = false) {
  const node = await getDb().securityTarget.findUnique({ where: { id } });
  if (!node || (!release && Date.now() - node.syncedAt.getTime() > 86400000))
    throw new HttpError(
      409,
      "TARGET_NOT_READY",
      "Target inventory unavailable or older than 24 hours",
    );
  return node;
}
export async function validateActionTarget(
  action: { nodeId: string; kind: string; serviceName: string | null },
  release = false,
) {
  const node = await readyTarget(action.nodeId, release);
  if (release) return node;
  const health = await agentHealth(node.baseUrl);
  if (health.responseCapable !== true)
    throw new HttpError(
      503,
      "RESPONSE_UNCONFIGURED",
      "Target has not enabled its managed response adapter",
    );
  if (action.kind === "service_restart") {
    const allowed = (process.env["SECURITY_FUSION_RESTART_ALLOWLIST"] ?? "")
      .split(",")
      .map((x) => x.trim());
    const normalizedService = action.serviceName?.replace(/\.service$/, "");
    // The general systemd snapshot is capped at 30 rows. Wazuh has its own
    // freshly collected unit state and can otherwise be omitted alphabetically.
    const active =
      normalizedService === "wazuh-agent" && health.wazuh
        ? health.wazuh.installed && health.wazuh.serviceStatus === "active"
        : health.services.some(
            (s) =>
              s.name?.replace(/\.service$/, "") === normalizedService &&
              s.status === "active",
          );
    if (!action.serviceName || !allowed.includes(action.serviceName) || !active)
      throw new HttpError(
        403,
        "SERVICE_RESTART_BLOCKED",
        "Service must be allowlisted and currently active",
      );
  } else {
    const tags = JSON.parse(node.tags) as string[];
    const meta = JSON.parse(node.metadata) as Record<string, unknown>;
    const protectedIds = (process.env["SECURITY_PROTECTED_TARGET_IDS"] ?? "")
      .split(",")
      .filter(Boolean);
    if (
      protectedIds.includes(node.id) ||
      tags.some((t) =>
        ["control-plane", "network-infrastructure"].includes(t),
      ) ||
      meta["securityIsolationPolicy"] !== "allow" ||
      meta["securityIsolationCapable"] !== true ||
      meta["securityAegisChannelVerified"] !== true
    )
      throw new HttpError(
        403,
        "ISOLATION_BLOCKED",
        "Isolation requires explicit policy, capability and verified recovery channel",
      );
  }
  return node;
}
