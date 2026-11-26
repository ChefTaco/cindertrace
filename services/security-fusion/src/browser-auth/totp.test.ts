import { expect, it } from "vitest";
import { base32Decode, totpCode, verifyTotp } from "./totp.js";
// RFC 6238 appendix B test vectors (SHA-1 secret "12345678901234567890"), last 6 digits.
const secret = Buffer.from("12345678901234567890");
it("matches the RFC 6238 SHA-1 test vectors", () => {
  for (const [time, code] of [[59, "287082"], [1111111109, "081804"], [1111111111, "050471"], [1234567890, "005924"], [2000000000, "279037"]] as const)
    expect(totpCode(secret, Math.floor(time / 30))).toBe(code);
});
it("decodes base32 and accepts one step of drift but no more", () => {
  expect(base32Decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")).toEqual(secret);
  expect(base32Decode("gezd gnbv gy3t qojq gezd gnbv gy3t qojq")).toEqual(secret);
  expect(() => base32Decode("not base32!")).toThrow();
  const now = 1111111111_000, step = Math.floor(now / 30_000);
  expect(verifyTotp(secret, totpCode(secret, step), now)).toBe(step);
  expect(verifyTotp(secret, totpCode(secret, step - 1), now)).toBe(step - 1);
  expect(verifyTotp(secret, totpCode(secret, step + 1), now)).toBe(step + 1);
  expect(verifyTotp(secret, totpCode(secret, step - 2), now)).toBeNull();
  expect(verifyTotp(secret, "12345", now)).toBeNull();
  expect(verifyTotp(secret, "abcdef", now)).toBeNull();
});
