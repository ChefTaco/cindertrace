export const UI_LOGIN_THRESHOLD = 3;
export const UI_LOGIN_WINDOW_MS = 15 * 60_000;
export const uiSource = (source: string): boolean =>
  source === "magnus_ui" ||
  ["aegis_ui", "security_console", "cindertrace_ui"].includes(source);
export function sourceInterpretations(source: string): string[] {
  return ["aegis_ui", "security_console", "cindertrace_ui"].includes(source)
    ? ["security_console", "aegis_ui", "cindertrace_ui"]
    : ["chattermost", "mattermost"].includes(source)
      ? ["mattermost", "chattermost"]
      : [source];
}
/** Derived identities only: historical records and signed payloads remain unchanged. */
export function entityInterpretations(
  type: string,
  canonical: string,
): string[] {
  if (!["account", "service"].includes(type)) return [canonical];
  const separator = canonical.indexOf(":");
  const source = separator < 0 ? canonical : canonical.slice(0, separator);
  const suffix = separator < 0 ? "" : canonical.slice(separator);
  return sourceInterpretations(source).map((alias) => alias + suffix);
}
/** Find a real event-time window containing the newly ingested failure, including
 * late arrivals. A success, throttled request or replay is never a failure. */
export function failureWindow<T extends { id: string; observedAt: Date }>(
  rows: T[],
  newId: string,
): T[] {
  const unique = [...new Map(rows.map((row) => [row.id, row])).values()].sort(
    (a, b) => a.observedAt.getTime() - b.observedAt.getTime(),
  );
  const current = unique.find((row) => row.id === newId);
  if (!current) return [];
  for (const end of unique) {
    if (end.observedAt < current.observedAt) continue;
    const window = unique.filter(
      (row) =>
        row.observedAt <= end.observedAt &&
        row.observedAt.getTime() >=
          end.observedAt.getTime() - UI_LOGIN_WINDOW_MS,
    );
    if (
      window.length >= UI_LOGIN_THRESHOLD &&
      window.some((row) => row.id === newId)
    )
      return window;
  }
  return [];
}
