// Exact reviewed Security Fusion table set. Update with every schema migration
// before the off-host backup can attest a complete export.
export const SECURITY_FUSION_TABLES = Object.freeze([
  "security_fusion_action_approvals",
  "security_fusion_actions",
  "security_fusion_approval_decisions",
  "security_fusion_assurance_packets",
  "security_fusion_case_activity",
  "security_fusion_case_entities",
  "security_fusion_case_events",
  "security_fusion_case_relationships",
  "security_fusion_cases",
  "security_fusion_collectors",
  "security_fusion_command_outbox",
  "security_fusion_deletion_receipts",
  "security_fusion_deliveries",
  "security_fusion_entities",
  "security_fusion_entity_aliases",
  "security_fusion_event_entities",
  "security_fusion_events",
  "security_fusion_evidence",
  "security_fusion_investigations",
  "security_fusion_nonces",
  "security_fusion_receipt_chain_heads",
  "security_fusion_rule_versions",
  "security_fusion_source_state",
  "security_fusion_telegram_decisions",
]);

const CINDERTRACE_V1_TABLES = Object.freeze([
  "security_fusion_action_approvals",
  "security_fusion_actions",
  "security_fusion_approval_decisions",
  "security_fusion_assurance_packets",
  "security_fusion_case_activity",
  "security_fusion_case_entities",
  "security_fusion_case_events",
  "security_fusion_case_relationships",
  "security_fusion_cases",
  "security_fusion_collectors",
  "security_fusion_command_outbox",
  "security_fusion_deletion_receipts",
  "security_fusion_deliveries",
  "security_fusion_entities",
  "security_fusion_entity_aliases",
  "security_fusion_event_entities",
  "security_fusion_events",
  "security_fusion_evidence",
  "security_fusion_investigations",
  "security_fusion_nonces",
  "security_fusion_receipt_chain_heads",
  "security_fusion_rule_versions",
  "security_fusion_source_state",
  "security_fusion_telegram_decisions",
]);

export function assertSecurityFusionTables(observed) {
  if (
    !Array.isArray(observed) ||
    observed.length !== SECURITY_FUSION_TABLES.length ||
    observed.some((name, index) => name !== SECURITY_FUSION_TABLES[index])
  )
    throw new Error(
      `Security table set differs from reviewed schema (expected ${SECURITY_FUSION_TABLES.length}, found ${observed?.length ?? "invalid"})`,
    );
}

export function securityTablesForProfile(profile = "current") {
  if (profile === "current") return [...SECURITY_FUSION_TABLES];
  if (profile === "cindertrace-v1") return [...CINDERTRACE_V1_TABLES];
  if (profile === "dedicated-v1")
    return SECURITY_FUSION_TABLES.filter(
      (name) => name !== "security_fusion_approval_decisions",
    );
  if (profile === "embedded-magnus-v1")
    return SECURITY_FUSION_TABLES.filter(
      (name) =>
        ![
          "security_fusion_approval_decisions",
          "security_fusion_assurance_packets",
          "security_fusion_telegram_decisions",
        ].includes(name),
    );
  throw new Error("Unrecognized Security Fusion schema profile");
}
