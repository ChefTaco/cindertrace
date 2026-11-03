import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
const db = {
  securityTarget: {
    findUnique: vi.fn(),
    findFirst: vi.fn(async () => ({ id: "n" })),
  },
};
const bridge = vi.hoisted(() => ({ request: vi.fn() }));
vi.mock("@cindertrace/integrations", () => ({ magnusRequest: bridge.request }));
vi.mock("../db/index.js", () => ({ getDb: () => db }));
import { readyTarget, validateActionTarget } from "./targets.js";
describe("Aegis target readiness", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });
  it("uses dedicated live Wazuh unit status when the capped service list omits it", async () => {
    db.securityTarget.findUnique.mockResolvedValue({
      id: "n",
      syncedAt: new Date(),
      baseUrl: "https://node:4100",
    });
    vi.stubEnv("SECURITY_FUSION_RESTART_ALLOWLIST", "wazuh-agent.service");
    const fetch = bridge.request;
    fetch.mockResolvedValueOnce({
      data: {
        responseCapable: true,
        services: [],
        wazuh: { installed: true, serviceStatus: "active" },
      },
    });
    await expect(
      validateActionTarget({
        nodeId: "n",
        kind: "service_restart",
        serviceName: "wazuh-agent.service",
      }),
    ).resolves.toMatchObject({ id: "n" });
    fetch.mockResolvedValueOnce({
      data: {
        responseCapable: true,
        services: [{ name: "wazuh-agent", status: "active" }],
        wazuh: { installed: true, serviceStatus: "failed" },
      },
    });
    await expect(
      validateActionTarget({
        nodeId: "n",
        kind: "service_restart",
        serviceName: "wazuh-agent.service",
      }),
    ).rejects.toThrow("currently active");
  });
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubEnv("MAGNUS_RESPONSE_URL", "https://magnus.example.com/response");
    vi.stubEnv("MAGNUS_RESPONSE_SECRET", "test-bridge-secret-".repeat(3));
  });
  it("blocks actions on stale inventory while allowing emergency release", async () => {
    db.securityTarget.findUnique.mockResolvedValue({
      id: "n",
      syncedAt: new Date(0),
    });
    await expect(readyTarget("n")).rejects.toThrow("older than 24 hours");
    await expect(readyTarget("n", true)).resolves.toMatchObject({ id: "n" });
  });
  it("protects configured control targets independently of inventory tags", async () => {
    db.securityTarget.findUnique.mockResolvedValue({
      id: "n",
      name: "security-control",
      hostname: "security.example.com",
      baseUrl: "https://security.example.com:4100",
      tags: "[]",
      metadata: JSON.stringify({
        securityIsolationCapable: true,
        securityIsolationPolicy: "allow",
        securityAegisChannelVerified: true,
      }),
      syncedAt: new Date(),
    });
    vi.stubEnv("SECURITY_PROTECTED_TARGET_IDS", "n");
    bridge.request.mockResolvedValue({
      data: { responseCapable: true, services: [] },
    });
    await expect(
      validateActionTarget({
        nodeId: "n",
        kind: "host_isolation",
        serviceName: null,
      }),
    ).rejects.toThrow("Isolation requires");
    vi.unstubAllGlobals();
  });
});
