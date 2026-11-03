export class PayloadTooLargeError extends Error {}
/** Bound actual streamed bytes; Content-Length is only an early rejection hint. */
export async function readBoundedBody(request: Request, maximum: number): Promise<string> {
  if (Number(request.headers.get('content-length')) > maximum) {
    await request.body?.cancel().catch(() => undefined);
    throw new PayloadTooLargeError('Request body exceeds its limit');
  }
  const reader = request.body?.getReader();
  if (!reader) return '';
  const chunks: Uint8Array[] = []; let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read(); if (done) break;
      size += value.byteLength;
      if (size > maximum) throw new PayloadTooLargeError('Request body exceeds its limit');
      chunks.push(value);
    }
    return Buffer.concat(chunks).toString('utf8');
  } finally { await reader.cancel().catch(() => undefined); }
}
