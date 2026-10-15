/**
 * Read an HTTP response body, refusing more than `maxBytes`. Remote feeds and
 * downloads are verified only after they are read, so an unbounded read lets a
 * hostile or broken server exhaust memory before verification can reject it.
 */
export async function readBodyCapped(res: Response, maxBytes: number): Promise<Buffer> {
  const declared = Number(res.headers?.get('content-length') ?? NaN);
  if (Number.isFinite(declared) && declared > maxBytes) {
    await res.body?.cancel().catch(() => undefined);
    throw new Error(`response is ${declared} bytes, over the ${maxBytes}-byte limit`);
  }
  if (!res.body) {
    // Bodiless stand-ins (test doubles) — a real Response streams
    const buf = typeof res.arrayBuffer === 'function' ? Buffer.from(await res.arrayBuffer()) : Buffer.alloc(0);
    if (buf.byteLength > maxBytes) throw new Error(`response exceeds the ${maxBytes}-byte limit`);
    return buf;
  }
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      throw new Error(`response exceeds the ${maxBytes}-byte limit`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}
