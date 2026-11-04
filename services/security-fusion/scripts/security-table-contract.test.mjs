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

it('keeps historical profiles fixed when additive lab tables enter the current schema', async () => {
  const {securityTablesForProfile} = await import('./security-table-contract.mjs');
  expect(securityTablesForProfile('cindertrace-v1')).toHaveLength(24);
  expect(securityTablesForProfile('cindertrace-v1').some(name => name.includes('_lab_'))).toBe(false);
  expect(securityTablesForProfile('embedded-magnus-v1').some(name => name.includes('_lab_'))).toBe(false);
  expect(securityTablesForProfile('dedicated-v1').some(name => name.includes('_lab_'))).toBe(false);
  expect(securityTablesForProfile('cindertrace-v2')).toEqual(SECURITY_FUSION_TABLES);
});

it('recognizes only the exact historical current archive table set', async () => {
  const {securityTablesForProfile, securityTablesForArchive} = await import('./security-table-contract.mjs');
  const old = securityTablesForProfile('cindertrace-v1');
  expect(securityTablesForArchive('current', old)).toEqual(old);
  expect(securityTablesForArchive('current', old.slice(1))).toEqual(SECURITY_FUSION_TABLES);
  expect(securityTablesForArchive('cindertrace-v2', old)).toEqual(SECURITY_FUSION_TABLES);
});
