import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, realpath } from "node:fs/promises";
import { extname, resolve } from "node:path";
import { identifyArtifactHeader, sampleEntropy } from "../domain/artifactTriage.js";

export interface TriageOptions {
  readonly hash?: "sample" | "full";
  readonly maxBytes?: number;
  readonly signal?: AbortSignal;
}

/** Bounded, read-only intake. No engine, subprocess, extraction or target execution. */
export const triageArtifact = async (path: string, options: TriageOptions = {}) => {
  const maxBytes = options.maxBytes ?? 64 * 1024 * 1024;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1)
    throw new RangeError("maxBytes must be a positive safe integer");
  if (options.hash !== undefined && options.hash !== "sample" && options.hash !== "full")
    throw new TypeError("hash must be sample or full");
  options.signal?.throwIfAborted();
  const canonicalPath = await realpath(resolve(path));
  const handle = await open(canonicalPath, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile()) throw new Error("Triage requires a regular file");
    if (before.size > BigInt(Number.MAX_SAFE_INTEGER))
      throw new RangeError("File size exceeds exact numeric range");
    const size = Number(before.size);
    if (options.hash === "full" && size > maxBytes)
      throw new RangeError(
        `Full hashing exceeds maxBytes (${maxBytes}); select sample hashing or increase the budget`,
      );
    const sampleLength = Math.min(size, 64 * 1024, maxBytes);
    const sample = Buffer.alloc(sampleLength);
    const digest = createHash("sha256");
    const readExactly = async (buffer: Buffer, position: number) => {
      let read = 0;
      while (read < buffer.length) {
        options.signal?.throwIfAborted();
        const result = await handle.read(buffer, read, buffer.length - read, position + read);
        if (result.bytesRead === 0)
          throw new Error("File changed or became truncated during triage");
        read += result.bytesRead;
      }
    };
    await readExactly(sample, 0);
    digest.update(sample);
    let bytesRead = sampleLength;
    if (options.hash === "full") {
      const chunk = Buffer.alloc(Math.min(1024 * 1024, size - bytesRead));
      while (bytesRead < size) {
        const selected = chunk.subarray(0, Math.min(chunk.length, size - bytesRead));
        await readExactly(selected, bytesRead);
        digest.update(selected);
        bytesRead += selected.length;
      }
    }
    options.signal?.throwIfAborted();
    const after = await handle.stat({ bigint: true });
    if (
      before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs ||
      before.ctimeNs !== after.ctimeNs
    )
      throw new Error("File changed during triage; retry with a stable snapshot");
    return {
      schema_version: 1,
      path: canonicalPath,
      size_bytes: size,
      extension_hint: extname(canonicalPath).toLowerCase() || null,
      identification: identifyArtifactHeader(sample),
      fingerprint: {
        algorithm: "sha256",
        scope: bytesRead === size ? "complete-file" : "prefix",
        bytes_hashed: bytesRead,
        digest: digest.digest("hex"),
      },
      sample: {
        offset: 0,
        length: sampleLength,
        entropy_bits_per_byte: sampleEntropy(sample),
      },
      limitations: [
        "Header routing is preliminary; use the proposed tools to validate structure and discover behavior.",
        "Tool names describe possible follow-ups, not installed engines or current session availability.",
        "Entropy describes this prefix only and does not establish encryption, compression or packing.",
        "No target code was executed. Concurrent same-size edits with restored timestamps may be undetectable; prefer a snapshot.",
      ],
    };
  } finally {
    await handle.close();
  }
};
