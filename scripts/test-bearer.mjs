// Short-lived bearers for the in-process test suites (core, lab and response integration).
// The API honours them only while CINDERTRACE_TEST_BEARER_SECRET is set in its own
// process, and a running API server refuses to start with it set.
import { randomBytes } from "node:crypto";
import { SignJWT } from "jose";
export function enableTestBearers() {
  process.env.CINDERTRACE_TEST_BEARER_SECRET ??= randomBytes(48).toString("hex");
}
export async function testBearer(role, userId = "fixture-" + role.toLowerCase(), lifetime = "60s") {
  enableTestBearers();
  return new SignJWT({ userId, role })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer("cindertrace-test")
    .setAudience("cindertrace-api")
    .setIssuedAt()
    .setExpirationTime(lifetime)
    .sign(new TextEncoder().encode(process.env.CINDERTRACE_TEST_BEARER_SECRET));
}
