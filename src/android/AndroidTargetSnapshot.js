import { createHash } from "node:crypto";
import { chmod, open, rm, stat } from "node:fs/promises";
import { join } from "node:path";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { AnalysisInputError, AnalysisCapabilityUnavailableError, } from "../domain/analysisErrorCore.js";
import { openRegularFile, assertRegularFileActive, sameRegularFileState, } from "../filesystem/RegularFile.js";
/** Bind decompiler input to the admitted artifact, even if the original changes. */
export const snapshotAndroidTarget = async (path, sha256, root, operation, signal) => {
    const snapshot = join(root, "target.apk");
    try {
        await copyAndroidSnapshot(path, snapshot, sha256, signal);
        assertRegularFileActive(signal);
        await chmod(snapshot, 0o400);
        return snapshot;
    }
    catch (cause) {
        if (!(cause instanceof AndroidSnapshotChangedError))
            throw cause;
        throw new AnalysisInputError(operation, { cause }, [
            {
                path: ["path"],
                reason: "invalid_value",
                message: `APK bytes changed after admission at ${path}; retry against a stable file.`,
            },
        ]);
    }
};
/** Fingerprint the actual immutable engine bytes executed for this observation. */
export const snapshotAndroidEngine = async (source, sha256, root, operation, signal) => {
    const path = join(root, "engine.jar");
    try {
        const observed = await copyAndroidSnapshot(source, path, sha256, signal);
        assertRegularFileActive(signal);
        await chmod(path, 0o400);
        return { path, sha256: observed };
    }
    catch (cause) {
        if (!(cause instanceof AndroidSnapshotChangedError))
            throw cause;
        throw new AnalysisCapabilityUnavailableError("jadx", operation, `PHXRE_JADX_MCP_JAR bytes changed during admission at ${source}; retry with a stable engine file.`, { cause });
    }
};
const copyAndroidSnapshot = async (sourcePath, snapshotPath, expectedSha256, signal) => {
    assertRegularFileActive(signal);
    const source = await openRegularFile(sourcePath, {
        symlinks: "follow",
        signal,
    });
    let destination;
    let inputStream;
    let outputStream;
    let removeSnapshot = false;
    let copiedBytes = 0;
    const hash = createHash("sha256");
    try {
        const initial = await source.stat();
        assertRegularFileActive(signal);
        const digest = new Transform({
            transform(chunk, _encoding, callback) {
                copiedBytes += chunk.length;
                if (copiedBytes > initial.size) {
                    callback(new AndroidSnapshotChangedError(`Android input grew while being copied: ${sourcePath}`));
                    return;
                }
                hash.update(chunk);
                callback(null, chunk);
            },
        });
        try {
            destination = await open(snapshotPath, "wx", 0o600);
            assertRegularFileActive(signal);
            inputStream = source.createReadStream({
                start: 0,
                end: initial.size,
                autoClose: false,
            });
            outputStream = destination.createWriteStream({ autoClose: false });
            await pipeline(inputStream, digest, outputStream, { signal });
            assertRegularFileActive(signal);
            await verifySourceState(source, sourcePath, initial, copiedBytes);
            const observedSha256 = hash.digest("hex");
            if (observedSha256 !== expectedSha256)
                throw new AndroidSnapshotChangedError(`Android snapshot digest mismatch for ${sourcePath}`);
            return observedSha256;
        }
        catch (cause) {
            removeSnapshot = destination !== undefined;
            throw cause;
        }
    }
    finally {
        // Non-auto-closing streams retain a reference to their FileHandle even
        // after pipeline completion. Release those references before awaiting
        // descriptor closure, after the admitted source state has been verified.
        inputStream?.destroy();
        outputStream?.destroy();
        try {
            await Promise.all([source.close(), destination?.close()]);
        }
        finally {
            if (removeSnapshot)
                await rm(snapshotPath, { force: true }).catch(() => undefined);
        }
    }
};
const verifySourceState = async (handle, path, initial, observedBytes) => {
    const [opened, currentPath] = await Promise.all([handle.stat(), stat(path)]);
    if (observedBytes !== initial.size ||
        !sameRegularFileState(initial, opened) ||
        !sameRegularFileState(initial, currentPath))
        throw new AndroidSnapshotChangedError(`Android input changed while being read: ${path}`);
};
class AndroidSnapshotChangedError extends Error {
    constructor(message, options) {
        super(message, options);
    }
}
