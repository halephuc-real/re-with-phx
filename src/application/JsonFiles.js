import { link, lstat, mkdtemp, open, realpath, rename, } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import { EvidenceFileError, } from "../domain/evidenceErrors.js";
import { AnalysisCancelledError, AnalysisResourceConstraintError, } from "../domain/analysisErrorCore.js";
import { err, ok } from "../domain/result.js";
import { JsonInputPhysicalReadFailure, JsonInputCancellationFailure, readJsonInputFile, readJsonObjectFile, } from "./JsonInputFile.js";
import { NonRegularFileReadError } from "../filesystem/RegularFile.js";
import { RegularFileCleanupFailure } from "./RegularFileRead.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { bindArtifactFileCleanup } from "../artifacts/ArtifactFileOperation.js";
import { AnalysisCleanupLeaseGroup, } from "../artifacts/AnalysisCleanupLease.js";
import { OwnedFileHandle } from "../filesystem/OwnedFileHandle.js";
import { OwnedStagedOutput } from "../filesystem/OwnedStagedOutput.js";
import { absoluteCallerPath } from "../filesystem/callerPath.js";
/** Read JSON data from a regular file at the caller-supplied path. */
export const readJsonFile = async (path, signal, resources) => readJsonFileInput(path, (selected) => readJsonInputFile(selected, "read_evidence_file", signal, resources), signal);
/** Read selected JSON members through the same regular-file error boundary. */
export const readJsonObjectMembersFile = (path, scans, signal, resources) => readJsonFileInput(path, (selected) => readJsonObjectFile(selected, "read_evidence_file", scans, signal, resources), signal);
const readJsonFileInput = async (path, read, signal) => {
    const requestedPath = absoluteCallerPath(path);
    try {
        const decoded = await read(requestedPath);
        if (!decoded.ok) {
            if (decoded.error instanceof AnalysisResourceConstraintError)
                return err(decoded.error);
            return err(new EvidenceFileError("read", "invalid-json", {
                cause: decoded.error.cause ??
                    new SyntaxError(decoded.error.issues[0]?.message ?? decoded.error.message),
                path: requestedPath,
            }));
        }
        return ok(decoded.value);
    }
    catch (cause) {
        if (cause instanceof RegularFileCleanupFailure)
            throw cause;
        if (cause instanceof AnalysisResourceConstraintError)
            return err(cause);
        if (cause instanceof JsonInputCancellationFailure)
            return err(new AnalysisCancelledError("read_evidence_file", {
                cause: cause.reason,
            }));
        if (cause instanceof JsonInputPhysicalReadFailure)
            return err(new EvidenceFileError("read", "io", {
                cause: cause.physicalCause,
                path: requestedPath,
            }));
        if (isJsonReadCancellation(cause, signal))
            return err(new AnalysisCancelledError("read_evidence_file", {
                cause: signal?.reason,
            }));
        return err(new EvidenceFileError("read", cause instanceof NonRegularFileReadError
            ? "not-file"
            : missingOrIo(cause), {
            cause,
            path: requestedPath,
        }));
    }
};
const isJsonReadCancellation = (cause, signal) => {
    if (signal?.aborted !== true)
        return false;
    if (cause === signal.reason)
        return true;
    return (cause instanceof Error &&
        cause.name === "AbortError" &&
        "code" in cause &&
        cause.code === "ABORT_ERR" &&
        cause.cause === signal.reason);
};
/** Atomically write text to the caller-supplied path. */
export const writeTextFile = async (encoded, path, overwrite, resources) => writeTextParts([encoded], path, overwrite, resources);
export function writeTextParts(parts, path, overwrite, resources, cancellation) {
    return resources
        .run(() => writeTextPartsOwned(parts, path, overwrite, resources, cancellation))
        .catch((cause) => {
        const cleanup = cause instanceof ArtifactReaderFailure && cause.cleanup !== undefined
            ? cause.cleanup
            : undefined;
        const error = new EvidenceFileError("write", "io", {
            cause,
            path: absoluteCallerPath(path),
            ...(cleanup === undefined ? {} : { cleanup }),
        });
        // A failed admission retry names its exact retained leases.
        bindArtifactFileCleanup(cause, error);
        return err(error);
    });
}
const writeTextPartsOwned = async (parts, path, overwrite, resources, cancellation) => {
    const requestedPath = absoluteCallerPath(path);
    try {
        assertWriteActive(cancellation);
        if (process.platform !== "win32" && requestedPath.endsWith("/"))
            return err(new EvidenceFileError("write", "not-file", { path: requestedPath }));
        const canonicalParent = await realpath(dirname(requestedPath));
        const destination = resolve(canonicalParent, basename(requestedPath));
        const existing = await lstat(destination).catch((cause) => {
            if (fileErrorCode(cause) === "ENOENT")
                return undefined;
            throw cause;
        });
        if (existing !== undefined) {
            if (!overwrite)
                return err(new EvidenceFileError("write", "exists", { path: requestedPath }));
            if (!existing.isFile() || existing.isSymbolicLink())
                return err(new EvidenceFileError("write", "not-file", { path: requestedPath }));
        }
        assertWriteActive(cancellation);
        const bytes = await publishFile(destination, parts, overwrite, resources, cancellation);
        return ok({ path: requestedPath, bytes });
    }
    catch (cause) {
        if (cause instanceof StagedOutputCleanupFailure) {
            const cleanup = {
                reason: failureMessage(cause.cleanupCause),
                resources: [cause.owner.directory],
            };
            if (cause.outcome.ok)
                return stagedCleanupFailure(new EvidenceFileError("write", "io", {
                    cause,
                    path: requestedPath,
                    cleanup,
                    published: { ...cause.outcome.value, path: requestedPath },
                }), cause.lease);
            if (cause.outcome.error instanceof AnalysisCancelledError)
                return stagedCleanupFailure(new AnalysisCancelledError(cause.outcome.error.operation, {
                    cause: cause.outcome.error.cause,
                    cleanupPrimary: cause.outcome.error,
                    cleanup,
                }), cause.lease);
            return stagedCleanupFailure(new EvidenceFileError("write", missingOrIo(cause.outcome.error), {
                cause,
                path: requestedPath,
                cleanup,
            }), cause.lease);
        }
        if (cancellation?.signal.aborted === true &&
            cause instanceof AnalysisCancelledError &&
            cause.operation === cancellation.operation)
            return err(cause);
        if (!overwrite && fileErrorCode(cause) === "EEXIST")
            return err(new EvidenceFileError("write", "exists", {
                cause,
                path: requestedPath,
            }));
        return err(new EvidenceFileError("write", missingOrIo(cause), {
            cause,
            path: requestedPath,
        }));
    }
};
/** The retained staging lease clears this error only when a retry confirms release. */
const stagedCleanupFailure = (error, lease) => {
    new AnalysisCleanupLeaseGroup(error, [lease]);
    return err(error);
};
/** A missing path or parent is a selection error, not a permission failure. */
const missingOrIo = (cause) => {
    const code = fileErrorCode(cause);
    return code === "ENOENT" || code === "ENOTDIR" ? "missing" : "io";
};
const publishFile = async (destination, parts, overwrite, resources, cancellation) => {
    const stagingDirectory = await mkdtemp(resolve(dirname(destination), ".phxre-write-"));
    const owner = await OwnedStagedOutput.create(stagingDirectory);
    let outcome;
    const staged = resolve(stagingDirectory, "content");
    try {
        const file = await open(staged, "wx", 0o600);
        owner.setFile(new OwnedFileHandle(file));
        let written;
        try {
            const bytes = await writeStagedParts(file, parts, cancellation);
            assertWriteActive(cancellation);
            await file.sync();
            written = ok(bytes);
        }
        catch (cause) {
            written = err(cause);
        }
        try {
            await owner.closeFile();
        }
        catch (cause) {
            if (written.ok)
                written = err(cause);
        }
        if (!written.ok)
            throw written.error;
        // Once submitted, atomic publication can win a later cancellation race.
        assertWriteActive(cancellation);
        await owner.assertReadyForPublication(staged);
        assertWriteActive(cancellation);
        if (overwrite) {
            await rename(staged, destination);
            owner.recordPublishedRename();
        }
        // A hard link publishes complete bytes atomically and cannot replace an existing name.
        else
            await link(staged, destination);
        outcome = ok({ path: destination, bytes: written.value });
    }
    catch (cause) {
        outcome = err(cause);
    }
    // One cleanup phase owns both the open descriptor (if any) and its staging directory.
    const released = await resources.release({
        kind: "staged-output",
        resource: owner.directory,
        output: owner,
    });
    if (released.kind === "failed")
        throw new StagedOutputCleanupFailure(outcome, released.cause, owner, released.lease);
    if (!outcome.ok)
        throw outcome.error;
    return outcome.value.bytes;
};
class StagedOutputCleanupFailure extends Error {
    outcome;
    cleanupCause;
    owner;
    lease;
    constructor(outcome, cleanupCause, owner, lease) {
        super("Staged output cleanup failed", {
            cause: outcome.ok ? cleanupCause : outcome.error,
        });
        this.outcome = outcome;
        this.cleanupCause = cleanupCause;
        this.owner = owner;
        this.lease = lease;
    }
}
const failureMessage = (cause) => cause instanceof Error ? cause.message || cause.name : String(cause);
const writeStagedParts = async (file, parts, cancellation) => {
    assertWriteActive(cancellation);
    const iterator = parts[Symbol.iterator]();
    let exhausted = false;
    let bytes = 0;
    try {
        for (;;) {
            assertWriteActive(cancellation);
            const part = iterator.next();
            if (part.done)
                exhausted = true;
            assertWriteActive(cancellation);
            if (part.done)
                return bytes;
            await file.writeFile(part.value, { encoding: "utf8" });
            bytes += Buffer.byteLength(part.value, "utf8");
        }
    }
    finally {
        if (!exhausted)
            iterator.return?.();
    }
};
const assertWriteActive = (cancellation) => {
    if (cancellation?.signal.aborted === true)
        throw new AnalysisCancelledError(cancellation.operation, {
            cause: cancellation.signal.reason,
        });
};
const fileErrorCode = (cause) => typeof cause === "object" && cause !== null && "code" in cause
    ? cause.code
    : undefined;
