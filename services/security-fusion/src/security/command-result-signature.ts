import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export interface SignedCommandResult {
  commandId: string;
  exitCode: number;
  stdout: string;
  stderr: string;
  durationMs: number;
  truncated: boolean;
  signature: string;
}

export function commandResultSigningPayload(
  result: Omit<SignedCommandResult, "signature">,
): string {
  return JSON.stringify({
    version: 1,
    commandId: result.commandId,
    exitCode: result.exitCode,
    durationMs: result.durationMs,
    stdoutSha256: createHash("sha256").update(result.stdout).digest("hex"),
    stderrSha256: createHash("sha256").update(result.stderr).digest("hex"),
    truncated: result.truncated,
  });
}

export function verifyCommandResultSignature(
  result: SignedCommandResult,
  activeSecret: string,
  previousSecret = "",
): boolean {
  if (activeSecret.length < 32 || !/^[a-f0-9]{64}$/i.test(result.signature))
    return false;
  const actual = Buffer.from(result.signature, "hex");
  const candidates = [
    activeSecret,
    ...(previousSecret.length >= 32 ? [previousSecret] : []),
  ];
  let matched = false;
  for (const secret of candidates) {
    const expected = createHmac("sha256", secret)
      .update(commandResultSigningPayload(result))
      .digest();
    matched =
      (actual.length === expected.length &&
        timingSafeEqual(actual, expected)) ||
      matched;
  }
  return matched;
}
