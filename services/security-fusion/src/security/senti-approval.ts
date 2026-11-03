import {
  createHash,
  createPublicKey,
  timingSafeEqual,
  verify,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { z } from "zod";
import { HttpError } from "../middleware/error-handler.js";

const identifier = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/);
const digest = z.string().regex(/^[a-f0-9]{64}$/);
const payloadFields = {
  proposal_id: identifier,
  proposal_revision: z.number().int().positive(),
  plan_sha256: digest,
  decision: z.enum(["approve", "reject"]),
  decision_id: identifier,
  decided_at: z.number().int().positive(),
  expires_at: z.number().int().positive(),
  actor_binding_sha256: digest,
  execution_id: identifier.nullable(),
} as const;
function validateBinding(
  p: { decision: "approve" | "reject"; execution_id: string | null },
  context: z.RefinementCtx,
) {
  if ((p.decision === "approve") !== (p.execution_id !== null))
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "Approval execution binding is invalid",
    });
}
const v2PayloadSchema = z
  .object({ version: z.literal(2), ...payloadFields })
  .strict()
  .superRefine(validateBinding);
const v3PayloadSchema = z
  .object({
    version: z.literal(3),
    source_channel: z.enum(["telegram", "iphone"]),
    ...payloadFields,
  })
  .strict()
  .superRefine(validateBinding);
const v4PayloadSchema = z
  .object({
    version: z.literal(4),
    source_channel: identifier,
    ...payloadFields,
  })
  .strict()
  .superRefine(validateBinding);
export const sentiApprovalPayloadSchema = z.union([
  v2PayloadSchema,
  v3PayloadSchema,
  v4PayloadSchema,
]);
export const sentiApprovalAssertionSchema = z
  .object({
    payload: sentiApprovalPayloadSchema,
    signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
  })
  .strict();
export type SentiApprovalPayload = z.infer<typeof sentiApprovalPayloadSchema>;

/** Python ensure_ascii=True compatible canonical JSON; key order is part of v2. */
export function approvalCanonicalJson(value: unknown): string {
  return JSON.stringify(value).replace(
    /[\u007f-\uffff]/g,
    (char) => "\\u" + char.charCodeAt(0).toString(16).padStart(4, "0"),
  );
}
export function approvalPayloadCanonical(p: SentiApprovalPayload): string {
  return approvalCanonicalJson({
    version: p.version,
    ...(p.version >= 3 && "source_channel" in p
      ? { source_channel: p.source_channel }
      : {}),
    proposal_id: p.proposal_id,
    proposal_revision: p.proposal_revision,
    plan_sha256: p.plan_sha256,
    decision: p.decision,
    decision_id: p.decision_id,
    decided_at: p.decided_at,
    expires_at: p.expires_at,
    actor_binding_sha256: p.actor_binding_sha256,
    execution_id: p.execution_id,
  });
}
export function approvalDigest(value: unknown): string {
  return createHash("sha256")
    .update(approvalCanonicalJson(value))
    .digest("hex");
}

function approvalPublicKey() {
  const inline = process.env["SENTI_APPROVAL_PUBLIC_KEY_PEM"];
  const encoded =
    process.env["SECURITY_APPROVAL_PUBLIC_KEY_B64"] ??
    process.env["SENTI_APPROVAL_PUBLIC_KEY_B64"];
  const path = process.env["SENTI_APPROVAL_PUBLIC_KEY_PATH"];
  if (!inline && !encoded && !path)
    throw new HttpError(
      403,
      "SENTI_APPROVAL_REQUIRED",
      "A configured external approval signer is required",
    );
  try {
    const key = createPublicKey(
      inline ??
        (encoded
          ? { key: Buffer.from(encoded, "base64"), format: "der", type: "spki" }
          : readFileSync(path!, "utf8")),
    );
    if (key.asymmetricKeyType !== "ed25519") throw new Error("wrong key type");
    return key;
  } catch {
    throw new HttpError(
      403,
      "SENTI_APPROVAL_REQUIRED",
      "The external approval signer is unavailable",
    );
  }
}

export function verifySentiApproval(raw: unknown): {
  payload: SentiApprovalPayload;
  assertionSha256: string;
} {
  const parsed = sentiApprovalAssertionSchema.safeParse(raw);
  const channel =
    parsed.success && parsed.data.payload.version === 3
      ? parsed.data.payload.source_channel
      : "telegram";
  const actor =
    parsed.success && parsed.data.payload.version === 4
      ? (process.env["SECURITY_APPROVAL_ACTOR_SHA256"] ?? "")
      : (process.env[
          channel === "iphone"
            ? "SENTI_IPHONE_ACTOR_SHA256"
            : "SENTI_TELEGRAM_ACTOR_SHA256"
        ] ?? "");
  if (!parsed.success || !/^[a-f0-9]{64}$/.test(actor))
    throw new HttpError(
      403,
      "SENTI_APPROVAL_REQUIRED",
      "An authenticated external decision is required",
    );
  const { payload, signature } = parsed.data;
  const canonical = approvalPayloadCanonical(payload);
  const signatureBytes = Buffer.from(signature, "base64url");
  if (
    signatureBytes.length !== 64 ||
    !verify(
      null,
      Buffer.from(
        `${payload.version === 4 ? "cindertrace.external-approval" : "magnus.senti-approval"}.v${payload.version}\n` +
          canonical,
      ),
      approvalPublicKey(),
      signatureBytes,
    ) ||
    !timingSafeEqual(
      Buffer.from(actor, "hex"),
      Buffer.from(payload.actor_binding_sha256, "hex"),
    )
  )
    throw new HttpError(
      403,
      "SENTI_APPROVAL_INVALID",
      "External decision authentication failed",
    );
  return {
    payload,
    assertionSha256: createHash("sha256")
      .update(canonical + "\n" + signature)
      .digest("hex"),
  };
}

export function requireFreshApproval(
  p: SentiApprovalPayload,
  now = Date.now(),
) {
  if (
    p.decided_at > now + 30_000 ||
    p.expires_at <= now ||
    p.decided_at >= p.expires_at ||
    p.expires_at - p.decided_at > 10 * 60_000
  )
    throw new HttpError(
      409,
      "SENTI_APPROVAL_EXPIRED",
      "External decision is expired or has an invalid lifetime",
    );
}
