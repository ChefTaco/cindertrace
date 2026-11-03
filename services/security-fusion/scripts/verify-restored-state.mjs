// Read-only integrity check; usable with either API's independently restored database.
import assert from "node:assert/strict";
import { resolve, relative, isAbsolute } from "node:path";
import { readFileSync, existsSync, lstatSync, createReadStream } from "node:fs";
import { createHmac, createHash } from "node:crypto";
if (process.env.CINDERTRACE_RESTORE_CONFIRM !== "empty-isolated-destination")
  throw new Error("Independent restore confirmation required");
const { getDb, disconnectDb } = await import(resolve("dist/db/index.js"));
const { deletionReceiptHash } = await import(
  resolve("dist/services/security-fusion-receipt-chain.js")
);
const { verifyAuditIntegrity, listAuditDays } = await import(
  resolve("dist/services/audit-service.js")
);
const canonical = (x) =>
  Array.isArray(x)
    ? "[" + x.map(canonical).join(",") + "]"
    : x && typeof x === "object"
      ? "{" +
        Object.entries(x)
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([k, v]) => JSON.stringify(k) + ":" + canonical(v))
          .join(",") +
        "}"
      : JSON.stringify(x);
try {
  const db = getDb();
  const receipts = await db.securityFusionDeletionReceipt.findMany({
    orderBy: { chainSequence: "asc" },
  });
  let previous = null;
  for (const row of receipts) {
    assert.equal(row.previousReceiptSha256, previous);
    if (row.chainVersion === 2)
      assert.equal(
        row.receiptSha256,
        deletionReceiptHash(row, previous, row.chainSequence),
      );
    previous = row.receiptSha256;
  }
  const head = await db.securityFusionReceiptChainHead.findUnique({
    where: { id: "security-fusion" },
  });
  if (head) assert.equal(head.headSha256, previous);
  const ledger = process.env.SECURITY_FUSION_RECEIPT_CHAIN_EXPORT;
  let ledgerRecords = 0;
  let ledgerHeadMatched = !head || head.chainSequence === 0;
  if (ledger && existsSync(ledger))
    for (const line of readFileSync(ledger, "utf8")
      .split("\n")
      .filter(Boolean)) {
      const { signatureHmacSha256, ...record } = JSON.parse(line);
      assert.equal(
        signatureHmacSha256,
        createHmac("sha256", process.env.SECURITY_FUSION_RECEIPT_SIGNING_KEY)
          .update(canonical(record))
          .digest("hex"),
      );
      assert(
        record.chainSequence <= (head?.chainSequence ?? 0),
        "Ledger contains effects beyond the restored database; current-state reconciliation is required",
      );
      if (
        record.chainSequence === head?.chainSequence &&
        record.headSha256 === head.headSha256
      )
        ledgerHeadMatched = true;
      ledgerRecords++;
    }
  if (head?.chainSequence)
    assert(
      ledgerHeadMatched,
      "No independently signed ledger checkpoint matches the restored head",
    );
  const evidenceBase = resolve(
    process.env.SECURITY_FUSION_EVIDENCE_DIR ??
      "state/security-fusion/evidence",
  );
  let evidenceVerified = 0,
    evidenceQuarantined = 0,
    cursor;
  for (;;) {
    const rows = await db.securityFusionEvidence.findMany({
      orderBy: { id: "asc" },
      take: 250,
      ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
    });
    if (!rows.length) break;
    for (const row of rows) {
      if (row.integrityStatus.startsWith("quarantined_")) {
        evidenceQuarantined++;
        continue;
      }
      const rel = relative(evidenceBase, resolve(row.storagePath));
      assert(
        rel && !rel.startsWith("..") && !isAbsolute(rel),
        "Evidence path escapes its restored storage boundary",
      );
      const stat = lstatSync(row.storagePath);
      assert(
        stat.isFile() && !stat.isSymbolicLink(),
        "Evidence must be a regular file",
      );
      const digest = createHash("sha256");
      for await (const chunk of createReadStream(row.storagePath))
        digest.update(chunk);
      assert.equal(
        digest.digest("hex"),
        row.sha256,
        "Restored evidence differs from its original digest",
      );
      if (row.byteSize > 0)
        assert.equal(stat.size, row.byteSize, "Restored evidence size differs");
      evidenceVerified++;
    }
    cursor = rows.at(-1).id;
  }
  const audit = [];
  for (const day of await listAuditDays()) {
    const result = await verifyAuditIntegrity(day);
    assert.equal(result.valid, true);
    audit.push({ day, ...result });
  }
  console.log(
    JSON.stringify({
      receipts: receipts.length,
      receiptHeadVerified: true,
      ledgerSignaturesVerified: ledgerRecords,
      ledgerHeadMatched,
      evidenceVerified,
      evidenceQuarantined,
      audit,
    }),
  );
} finally {
  await disconnectDb();
}
