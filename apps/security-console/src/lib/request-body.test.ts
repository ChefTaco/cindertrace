import { expect, it } from 'vitest';
import { readBoundedBody } from './request-body';
it('rejects streamed bytes even with absent or misleading Content-Length', async () => {
  for (const headers of [{}, {'content-length':'1'}]) {
    const stream = new ReadableStream({start(c){c.enqueue(new Uint8Array(5));c.enqueue(new Uint8Array(5));c.close();}});
    const request = new Request('https://example.com', {method:'POST',headers,body:stream,duplex:'half'} as RequestInit);
    await expect(readBoundedBody(request,9)).rejects.toThrow('exceeds');
  }
});
it('counts UTF-8 bytes and admits the exact byte limit', async () => {
  await expect(readBoundedBody(new Request('https://example.com',{method:'POST',body:'éé'}),4)).resolves.toBe('éé');
  await expect(readBoundedBody(new Request('https://example.com',{method:'POST',body:'éé'}),3)).rejects.toThrow('exceeds');
});
