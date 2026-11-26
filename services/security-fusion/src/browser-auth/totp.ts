import { createHmac, timingSafeEqual } from "node:crypto";

/** RFC 6238 time-based one-time codes: HMAC-SHA1, 6 digits, 30-second steps. */
const STEP_SECONDS = 30;
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** Decode an RFC 4648 base32 secret (spaces and padding ignored, case-insensitive). */
export function base32Decode(value: string): Buffer {
  const clean = value.replace(/[\s=]/g, "").toUpperCase();
  if (!/^[A-Z2-7]+$/.test(clean)) throw new Error("Invalid base32 secret");
  let bits = 0, buffer = 0;
  const out: number[] = [];
  for (const char of clean) {
    buffer = (buffer << 5) | ALPHABET.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }
  return Buffer.from(out);
}

export function totpCode(secret: Buffer, step: number): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const digest = createHmac("sha1", secret).update(counter).digest();
  const offset = digest[digest.length - 1]! & 0x0f;
  const binary = (digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return String(binary).padStart(6, "0");
}

/**
 * The time step `code` belongs to, allowing one step of clock drift either way, or null.
 * The caller must refuse a step at or before the last one used (replay).
 */
export function verifyTotp(secret: Buffer, code: string, now = Date.now()): number | null {
  if (!/^\d{6}$/.test(code)) return null;
  const current = Math.floor(now / 1000 / STEP_SECONDS);
  let matched: number | null = null;
  // Check every candidate step, so timing does not reveal which one matched.
  for (const step of [current - 1, current, current + 1]) {
    const expected = Buffer.from(totpCode(secret, step));
    if (timingSafeEqual(expected, Buffer.from(code)) && matched === null) matched = step;
  }
  return matched;
}
