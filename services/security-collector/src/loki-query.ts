import { createHash } from 'node:crypto';

export interface LokiEntry { timestampNs: bigint; line: string; labels: Record<string, string>; fingerprint: string }

export function lokiFingerprint(timestamp: string, line: string, labels: Record<string, string>): string {
  return createHash('sha256').update(JSON.stringify([timestamp, line, Object.entries(labels).sort()])).digest('hex');
}

/** Loki query_range has no offset. Grow the page until the whole time window fits;
 * fail closed at the ceiling rather than advancing a cursor past unseen rows. */
export async function fetchCompleteLokiWindow(
  baseUrl: string, query: string, startNs: bigint, endNs: bigint, initialLimit: number,
  fetchPage: (url: URL) => Promise<unknown>, maxLimit = 10_000,
): Promise<LokiEntry[]> {
  if (!Number.isSafeInteger(initialLimit) || initialLimit < 1 || initialLimit > maxLimit) throw Error('Invalid Loki page limit');
  let limit = initialLimit;
  for (;;) {
    const url = new URL(`${baseUrl}/loki/api/v1/query_range`);
    url.searchParams.set('query', query);
    url.searchParams.set('start', startNs.toString());
    url.searchParams.set('end', endNs.toString());
    url.searchParams.set('limit', String(limit));
    url.searchParams.set('direction', 'forward');
    const body = await fetchPage(url);
    if (!body || typeof body !== 'object' || (body as {status?: unknown}).status !== 'success') throw Error('Loki returned an unsuccessful response');
    const data = (body as {data?: {result?: unknown}}).data;
    if (!Array.isArray(data?.result)) throw Error('Loki response has no result list');
    const entries: LokiEntry[] = [];
    for (const stream of data.result) {
      if (!stream || typeof stream !== 'object' || !Array.isArray(stream.values)) throw Error('Invalid Loki stream');
      const labels = stream.stream;
      if (!labels || typeof labels !== 'object' || Array.isArray(labels) ||
        Object.values(labels).some(value => typeof value !== 'string')) throw Error('Invalid Loki labels');
      for (const value of stream.values) {
        if (!Array.isArray(value) || value.length !== 2 || typeof value[0] !== 'string' || !/^\d+$/u.test(value[0]) || typeof value[1] !== 'string') throw Error('Invalid Loki entry');
        entries.push({ timestampNs: BigInt(value[0]), line: value[1], labels,
          fingerprint: lokiFingerprint(value[0], value[1], labels) });
      }
    }
    const sorted = entries.sort((a,b) => a.timestampNs < b.timestampNs ? -1 : a.timestampNs > b.timestampNs ? 1 : a.fingerprint.localeCompare(b.fingerprint));
    if (entries.length < limit) return sorted;
    // All timestamps before the last row are complete in a forward page.
    // The last timestamp might be cut in half, so leave it for the next poll.
    const complete = sorted.filter(entry => entry.timestampNs < sorted.at(-1)!.timestampNs);
    if (complete.length > 0) return complete;
    if (limit === maxLimit) throw Error(`Loki query saturated the ${maxLimit} entry safety limit; checkpoint held`);
    limit = Math.min(maxLimit, limit * 2);
  }
}
