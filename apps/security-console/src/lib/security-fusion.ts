import { securityFetch } from "@/lib/security-api";

export type FusionSeverity = "info" | "low" | "medium" | "high" | "critical";

export interface FusionCase {
  id: string;
  title: string;
  severity: FusionSeverity;
  status: string;
  confidence: number;
  summary: string;
  firstSeenAt: string;
  lastSeenAt: string;
  recommendedInvestigation: string[];
  evidenceSteps: string[];
}

export interface FusionEvent {
  id: string;
  eventId: string;
  source: string;
  kind: string;
  observedAt: string;
  severity: FusionSeverity;
  confidence: number;
  summary: string;
  integritySha256: string;
  confidenceContribution?: number;
  attributes?: Record<string, unknown>;
}

export interface FusionEntity {
  id: string;
  type: string;
  canonical: string;
  label: string;
  lastSeenAt: string;
}

export interface FusionSource {
  source: string;
  status: string;
  lastEventAt?: string;
  lastSuccessAt?: string;
  lastError?: string;
}

export interface FusionCollector {
  id: string;
  displayName: string;
  allowedSources: string[];
  schemaVersion: string;
  dataClassification: string;
  status: string;
  cursorHealth: string;
  lastReceiptAt?: string;
  lastSuccessAt?: string;
  revokedAt?: string;
}

export async function fusionFetch<T>(path: string): Promise<T> {
  const result = await securityFetch<{ success: boolean; data: T }>(
    `security-fusion/${path}`,
  );
  return result.data;
}

export const severityClass: Record<FusionSeverity, string> = {
  info: "text-text-muted border-border",
  low: "text-primary border-primary/30",
  medium: "text-warning border-warning/40",
  high: "text-accent border-accent/40 shadow-[0_0_10px_var(--color-glow-accent)]",
  critical: "text-danger border-danger/50 bg-danger/5 shadow-[0_0_14px_var(--color-glow-danger)]",
};

/** Product labels do not alter historical source IDs or signed event contents. */
export function sourceLabel(source: string): string {
  if (["aegis_ui", "security_console", "cindertrace_ui"].includes(source)) return "Cindertrace console";
  if (["chattermost", "mattermost"].includes(source)) return "Mattermost-compatible audit";
  if (source === "magnus_ui") return "Magnus console";
  return source.replaceAll("_", " ");
}
