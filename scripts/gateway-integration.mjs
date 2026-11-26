// Disposable end-to-end check of the published gateway: sign-in and an API call through it,
// then per-client sign-in throttling. Run from a freshly initialized Compose installation
// directory with the stack up. It exhausts this host's sign-in allowance for 15 minutes.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import https from "node:https";
import { readEnvironment } from "./upgrade-policy.mjs";
assert.equal(
  process.env.CINDERTRACE_GATEWAY_TEST_CONFIRM,
  "disposable-installation",
  "The gateway check requires disposable-installation confirmation",
);
const env = readEnvironment(readFileSync(".env", "utf8"));
const origin = env.CINDERTRACE_PUBLIC_ORIGIN ?? env.DASHBOARD_PUBLIC_ORIGIN;
const ca = readFileSync("certs/server.crt");
const password = /^Password: (.+)$/m.exec(readFileSync("state/initial-credentials.txt", "utf8"))[1];
function request(path, { method = "GET", cookie, body, headers = {} } = {}) {
  return new Promise((done, reject) => {
    const req = https.request(origin + path, {
      method, ca,
      headers: { origin, "content-type": "application/json", ...(cookie ? { cookie } : {}), ...headers },
    }, (res) => {
      let text = "";
      res.on("data", (chunk) => (text += chunk));
      res.on("end", () => done({ status: res.statusCode, headers: res.headers, text }));
    });
    req.on("error", reject);
    req.end(body ? JSON.stringify(body) : undefined);
  });
}
const login = (username, pass, headers) =>
  request("/api/cindertrace/auth/local/login", { method: "POST", body: { username, password: pass }, headers });

const signedIn = await login("admin", password);
assert.equal(signedIn.status, 200, "Sign-in through the gateway");
const cookie = signedIn.headers["set-cookie"][0].split(";")[0];
const overview = await request("/api/cindertrace/security-fusion/overview", { cookie });
assert.equal(overview.status, 200, "API call through the gateway");
assert.equal(JSON.parse(overview.text).success, true);
assert.equal((await request("/api/cindertrace/auth/local/logout", { method: "POST", cookie })).status, 200);

// Failed sign-ins fill this client's allowance (20 per 15 minutes), whatever forwarding
// header the caller sends: the gateway appends the address it saw, and the API reads that.
let failures = 0, throttled;
for (let attempt = 0; attempt < 25 && !throttled; attempt++) {
  const spoofed = `198.51.100.${attempt + 1}`;
  const response = await login("fixture-" + randomBytes(6).toString("hex"), "wrong", { "x-forwarded-for": spoofed });
  if (response.status === 429) throttled = response;
  else {
    assert.equal(response.status, 401);
    failures++;
  }
}
assert(throttled, "Sign-in is throttled after repeated failures");
assert.equal(failures, 20);
assert(Number(throttled.headers["retry-after"]) > 0);
assert.equal((await login("admin", password)).status, 429, "The throttled client stays throttled");

// Another client (the API container, reaching the gateway over the Compose network) still signs in.
const other = execFileSync("docker", [
  "compose", "exec", "-T", "-e", "CHECK_ORIGIN=" + origin, "-e", "CHECK_PASSWORD=" + password, "api", "node", "-e",
  "fetch('https://gateway:3444/api/cindertrace/auth/local/login',{method:'POST',headers:{origin:process.env.CHECK_ORIGIN,'content-type':'application/json'},body:JSON.stringify({username:'admin',password:process.env.CHECK_PASSWORD})}).then(r=>console.log(r.status))",
], { encoding: "utf8" }).trim();
assert.equal(other, "200", "A different client is not throttled by this one");
console.log(JSON.stringify({ gateway: "passed", signIn: true, apiCall: true, throttledAfter: failures, spoofedForwardingIgnored: true, otherClientSignedIn: true }));
