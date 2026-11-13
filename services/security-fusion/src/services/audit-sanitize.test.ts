import { expect, it } from "vitest";
import { sanitizeDetails } from "./audit-service.js";

it("redacts sensitive keys whatever their letter case", () => {
  expect(
    sanitizeDetails({
      AccessToken: "fixture-a",
      APIKEY: "fixture-b",
      RefreshToken: "fixture-c",
      PrivateKey: "fixture-d",
      Authorization: "fixture-e",
      nodeToken: "fixture-f",
      nested: { JwtSecret: "fixture-g", kept: "visible" },
    }),
  ).toEqual({
    AccessToken: "[REDACTED]",
    APIKEY: "[REDACTED]",
    RefreshToken: "[REDACTED]",
    PrivateKey: "[REDACTED]",
    Authorization: "[REDACTED]",
    nodeToken: "[REDACTED]",
    nested: { JwtSecret: "[REDACTED]", kept: "visible" },
  });
});

it("keeps nested arrays as arrays and redacts inside them", () => {
  expect(
    sanitizeDetails({
      ports: [[80, 443], [22]],
      rows: [[{ password: "fixture", name: "a" }], "text", null, 7],
    }),
  ).toEqual({
    ports: [[80, 443], [22]],
    rows: [[{ password: "[REDACTED]", name: "a" }], "text", null, 7],
  });
});

it("keeps the first hundred items of an array", () => {
  const cleaned = sanitizeDetails({ items: Array.from({ length: 150 }, (_, index) => index) });
  expect(cleaned["items"]).toHaveLength(100);
});
