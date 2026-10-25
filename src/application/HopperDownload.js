/** Maximum admitted vendor response bytes, shared by Hopper setup adapters. */
export const HOPPER_DOWNLOAD_BYTES = 100000000;
/** Bound observed response bytes before retaining them, including chunked bodies. */
export const downloadHopperPackage = async (url, options = {}) => {
    const timeoutMs = options.timeoutMs ?? 120000;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120000)
        throw new RangeError("Invalid Hopper response time budget");
    const deadline = AbortSignal.timeout(timeoutMs);
    const maxBytes = options.maxBytes ?? HOPPER_DOWNLOAD_BYTES;
    if (!Number.isSafeInteger(maxBytes) ||
        maxBytes < 1 ||
        maxBytes > HOPPER_DOWNLOAD_BYTES)
        throw new RangeError("Invalid Hopper response byte budget");
    const response = await fetch(url, {
        headers: { accept: "application/json", "user-agent": "phxre-installer" },
        signal: options.signal === undefined
            ? deadline
            : AbortSignal.any([options.signal, deadline]),
    });
    const refused = { ok: false, bytes: new Uint8Array() };
    if (!response.ok ||
        Number(response.headers.get("content-length")) > maxBytes) {
        await response.body?.cancel();
        return refused;
    }
    if (response.body === null)
        return { ok: true, bytes: new Uint8Array() };
    const reader = response.body.getReader();
    const chunks = [];
    let bytes = 0;
    try {
        while (true) {
            const chunk = await reader.read();
            if (chunk.done)
                return { ok: true, bytes: Buffer.concat(chunks, bytes) };
            if (chunk.value.byteLength > maxBytes - bytes) {
                await reader.cancel();
                return refused;
            }
            chunks.push(chunk.value);
            bytes += chunk.value.byteLength;
        }
    }
    finally {
        reader.releaseLock();
    }
};
