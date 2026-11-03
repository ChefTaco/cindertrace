import { describe, it, expect } from "vitest";
import {
  failureWindow,
  entityInterpretations,
  sourceInterpretations,
  UI_LOGIN_WINDOW_MS,
} from "./ui-login-rule.js";
const row = (id: string, seconds: number) => ({
  id,
  observedAt: new Date(1_800_000_000_000 + seconds * 1000),
});
describe("three failed logins in fifteen minutes", () => {
  it("groups public and legacy console identities without conflating other accounts", () => {
    expect(sourceInterpretations("cindertrace_ui")).toContain("aegis_ui");
    expect(entityInterpretations("account", "aegis_ui:example")).toEqual(
      entityInterpretations("account", "cindertrace_ui:example"),
    );
    expect(entityInterpretations("user", "aegis_ui:example")).toEqual([
      "aegis_ui:example",
    ]);
    expect(sourceInterpretations("magnus_ui")).toEqual(["magnus_ui"]);
  });
  it("does not trigger for one or two failures", () => {
    expect(failureWindow([row("a", 0)], "a")).toEqual([]);
    expect(failureWindow([row("a", 0), row("b", 10)], "b")).toEqual([]);
  });
  it("triggers on the third and includes the first two as evidence", () => {
    expect(
      failureWindow([row("a", 0), row("b", 10), row("c", 20)], "c").map(
        (x) => x.id,
      ),
    ).toEqual(["a", "b", "c"]);
  });
  it("excludes old failures outside the window", () => {
    expect(
      failureWindow(
        [row("a", 0), row("b", 10), row("c", UI_LOGIN_WINDOW_MS / 1000 + 1)],
        "c",
      ),
    ).toEqual([]);
  });
  it("does not count replayed IDs twice", () => {
    expect(
      failureWindow([row("a", 0), row("a", 0), row("b", 10)], "b"),
    ).toEqual([]);
  });
  it("detects a threshold reached through out-of-order delivery", () => {
    expect(
      failureWindow([row("c", 20), row("a", 0), row("b", 10)], "a"),
    ).toHaveLength(3);
  });
});
