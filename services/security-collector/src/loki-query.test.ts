import { describe, expect, it } from 'vitest';
import { fetchCompleteLokiWindow, lokiFingerprint } from './loki-query.js';

describe('Loki timestamp boundary', () => {
  it('grows a saturated page and consumes 1,501 unique entries at one timestamp', async () => {
    const timestamp = '1780000000000000000';
    const lines = Array.from({ length: 1501 }, (_, i) => `event-${i}`);
    const limits: number[] = [];
    const fetchPage = async (url: URL) => {
      const limit = Number(url.searchParams.get('limit'));
      limits.push(limit);
      return { status: 'success', data: { result: [{ stream: { host: 'gateway-1' },
        values: lines.slice(0, limit).map(line => [timestamp, line]) }] } };
    };
    const entries = await fetchCompleteLokiWindow('https://logs.example.invalid:3443', '{}', BigInt(timestamp),
      BigInt(timestamp), 1000, fetchPage);
    expect(limits).toEqual([1000, 2000]);
    expect(entries).toHaveLength(1501);
    expect(new Set(entries.map(entry => entry.fingerprint)).size).toBe(1501);
    const consumed = new Set(entries.map(entry => entry.fingerprint));
    const replay = await fetchCompleteLokiWindow('https://logs.example.invalid:3443', '{}', BigInt(timestamp),
      BigInt(timestamp), 1000, fetchPage);
    expect(replay.filter(entry => !consumed.has(entry.fingerprint))).toHaveLength(0);
    expect(lokiFingerprint(timestamp, lines[0]!, {host:'gateway-1'})).toBe(entries.find(entry => entry.line === lines[0])?.fingerprint);
  });

  it('refuses to advance when a timestamp exceeds the bounded page ceiling', async () => {
    const fetchPage = async (url: URL) => ({ status: 'success', data: { result: [{ stream: {host:'gateway-1'},
      values: Array.from({length:Number(url.searchParams.get('limit'))}, (_, i) => ['1780000000000000000', `event-${i}`]) }] } });
    await expect(fetchCompleteLokiWindow('https://logs.example.invalid', '{}', 1n, 2n, 1000, fetchPage, 2000))
      .rejects.toThrow('checkpoint held');
  });
  it('returns only complete timestamps from a saturated multi-timestamp page', async () => {
    const fetchPage = async (url: URL) => ({ status: 'success', data: { result: [{ stream: {host:'gateway-1'},
      values: Array.from({length:1200}, (_, i) => [i < 900 ? '1000' : '1001', `event-${i}`])
        .slice(0, Number(url.searchParams.get('limit'))) }] } });
    const first = await fetchCompleteLokiWindow('https://logs.example.invalid', '{}', 1000n, 2000n, 1000, fetchPage);
    expect(first).toHaveLength(900);
    expect(first.every(entry => entry.timestampNs === 1000n)).toBe(true);
  });
});
