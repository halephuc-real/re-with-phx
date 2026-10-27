import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, it } from "vitest";
import { triageArtifact } from "./triageArtifact.js";

let directory: string;
beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), "phxre-triage-test-"));
});
afterEach(async () => {
  await rm(directory, { recursive: true, force: true });
});
const hash = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");

it("uses content despite a misleading suffix and preserves the input", async () => {
  const file = join(directory, "fake.exe");
  const bytes = Buffer.from("0061736d01000000", "hex");
  await writeFile(file, bytes);
  const result = await triageArtifact(file);
  expect(result.identification.format).toBe("wasm");
  expect(result.extension_hint).toBe(".exe");
  expect(result.fingerprint.digest).toBe(hash(bytes));
  expect(await readFile(file)).toEqual(bytes);
});

it("distinguishes prefix and complete hashes", async () => {
  const file = join(directory, "large.bin");
  const bytes = Buffer.alloc(2 * 1024 * 1024 + 7, 42);
  bytes[bytes.length - 1] = 100;
  await writeFile(file, bytes);
  const sample = await triageArtifact(file);
  expect(sample.fingerprint.scope).toBe("prefix");
  expect(sample.fingerprint.digest).toBe(hash(bytes.subarray(0, 65536)));
  const full = await triageArtifact(file, { hash: "full" });
  expect(full.fingerprint.scope).toBe("complete-file");
  expect(full.fingerprint.digest).toBe(hash(bytes));
});

it("enforces budgets, rejects non-files and respects cancellation", async () => {
  const file = join(directory, "sample.bin");
  await writeFile(file, Buffer.alloc(512));
  expect((await triageArtifact(file, { maxBytes: 7 })).sample.length).toBe(7);
  await expect(triageArtifact(file, { hash: "full", maxBytes: 511 })).rejects.toThrow(
    "exceeds maxBytes",
  );
  await expect(triageArtifact(directory)).rejects.toThrow();
  await expect(
    triageArtifact(join(directory, "missing"), {
      signal: AbortSignal.abort(new Error("cancelled by caller")),
    }),
  ).rejects.toThrow("cancelled by caller");
});
