export async function boundedLoginBody(request: Request): Promise<string> {
  const declared = request.headers.get("Content-Length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > 4096))
    throw Error("Request too large");
  if (!request.body) return "";
  const reader = request.body.getReader(),
    parts: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const item = await reader.read();
      if (item.done) break;
      size += item.value.byteLength;
      if (size > 4096) {
        await reader.cancel();
        throw Error("Request too large");
      }
      parts.push(item.value);
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(parts).toString("utf8");
}
