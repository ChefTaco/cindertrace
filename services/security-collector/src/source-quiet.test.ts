import { describe, expect, it } from "vitest";
import { securityFusionSourceSchema } from "@cindertrace/contracts";
import { quietSourceError, readQuietSourcePolicy } from "./source-quiet.js";

const known = securityFusionSourceSchema.options;
const started = new Date("2026-11-18T00:00:00.000Z");

describe("quiet source signal", () => {
  it("watches netflow for six hours by default", () => {
    const policy = readQuietSourcePolicy({}, known);
    expect(policy.hours).toBe(6);
    expect([...policy.sources]).toEqual(["netflow"]);
  });
  it("rejects unknown sources and out-of-range hours", () => {
    expect(() => readQuietSourcePolicy({ SECURITY_FUSION_QUIET_SOURCES: "netflow,firewall" }, known)).toThrow(/firewall/u);
    expect(() => readQuietSourcePolicy({ SECURITY_FUSION_QUIET_AFTER_HOURS: "-1" }, known)).toThrow();
    expect(() => readQuietSourcePolicy({ SECURITY_FUSION_QUIET_AFTER_HOURS: "soon" }, known)).toThrow();
  });
  it("degrades a watched source only after the quiet period", () => {
    const policy = readQuietSourcePolicy({ SECURITY_FUSION_QUIET_AFTER_HOURS: "2" }, known);
    const at = (hours: number) => new Date(started.getTime() + hours * 3_600_000);
    expect(quietSourceError("netflow", undefined, started, at(1.5), policy)).toBeNull();
    expect(quietSourceError("netflow", undefined, started, at(2.5), policy)).toMatch(/since the collector started/u);
    expect(quietSourceError("netflow", at(1).toISOString(), started, at(2.5), policy)).toBeNull();
    expect(quietSourceError("netflow", at(1).toISOString(), started, at(3.5), policy)).toMatch(/last event 2026-11-18T01:00:00.000Z/u);
    // An event older than the collector start never makes the source quiet at once.
    expect(quietSourceError("netflow", "2026-11-10T00:00:00.000Z", started, at(1), policy)).toBeNull();
  });
  it("ignores unwatched sources and can be turned off", () => {
    const policy = readQuietSourcePolicy({}, known);
    const late = new Date(started.getTime() + 48 * 3_600_000);
    expect(quietSourceError("unifi_ids", undefined, started, late, policy)).toBeNull();
    const off = readQuietSourcePolicy({ SECURITY_FUSION_QUIET_AFTER_HOURS: "0" }, known);
    expect(quietSourceError("netflow", undefined, started, late, off)).toBeNull();
  });
});
