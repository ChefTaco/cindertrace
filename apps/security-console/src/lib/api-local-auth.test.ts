import { afterEach, expect, it, vi } from "vitest";
import { apiLocalRequest, forwardedSessionCookie } from "./api-local-auth";
afterEach(() => vi.unstubAllEnvs());
it("delegates to a verified product origin with only the native cookie and exact browser Origin", async () => {
  vi.stubEnv("CINDERTRACE_API_URL", "https://security.example.com");
  vi.stubEnv("DASHBOARD_PUBLIC_ORIGIN", "https://console.example.com");
  const request = vi
    .fn<typeof fetch>()
    .mockResolvedValue(Response.json({ ok: true }));
  await apiLocalRequest(
    "logout",
    { token: "obviously.fake.session", all: true },
    request,
  );
  const [url, init] = request.mock.calls[0]!;
  expect(url).toBe(
    "https://security.example.com/api/v1/auth/local/logout?all=true",
  );
  const headers = new Headers(init?.headers);
  expect(headers.get("Cookie")).toBe(
    "cindertrace_session=obviously.fake.session",
  );
  expect(headers.get("Authorization")).toBeNull();
  expect(headers.get("Origin")).toBe("https://console.example.com");
  expect(init?.redirect).toBe("error");
  vi.stubEnv("CINDERTRACE_API_URL", "http://security.example.com");
  await expect(apiLocalRequest("session", {}, request)).rejects.toThrow(
    /Verified/,
  );
  expect(request).toHaveBeenCalledOnce();
});
it("refuses session cookies that widen the browser domain or drop transport protection", () => {
  expect(() =>
    forwardedSessionCookie(
      new Response(null, {
        headers: {
          "set-cookie":
            "cindertrace_session=obviously.fake.session; Path=/; HttpOnly; Secure; SameSite=Lax; Domain=example.com",
        },
      }),
    ),
  ).toThrow();
  expect(() =>
    forwardedSessionCookie(
      new Response(null, {
        headers: {
          "set-cookie":
            "cindertrace_session=obviously.fake.session; Path=/; HttpOnly; SameSite=Lax",
        },
      }),
    ),
  ).toThrow();
});
