import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  SECURITY_FUSION_TABLES,
  assertSecurityFusionTables,
} from "./security-table-contract.mjs";

describe("Security Fusion export table contract", () => {
  it("matches every current Prisma Security Fusion table exactly", () => {
    const schema = readFileSync(
      fileURLToPath(new URL("../prisma/schema.prisma", import.meta.url)),
      "utf8",
    );
    const names = [...schema.matchAll(/@@map\("(security_fusion_[a-z_]+)"\)/g)]
      .map((match) => match[1])
      .sort();
    expect(names).toEqual(SECURITY_FUSION_TABLES);
    expect(() => assertSecurityFusionTables(names)).not.toThrow();
  });

  it("rejects a missing, added, or substituted table before writing an archive", () => {
    const names = [...SECURITY_FUSION_TABLES];
    expect(() => assertSecurityFusionTables(names.slice(1))).toThrow(
      "table set differs",
    );
    expect(() =>
      assertSecurityFusionTables([...names, "security_fusion_unreviewed"]),
    ).toThrow("table set differs");
    names[0] = "security_fusion_unreviewed";
    expect(() => assertSecurityFusionTables(names)).toThrow(
      "table set differs",
    );
  });
});
