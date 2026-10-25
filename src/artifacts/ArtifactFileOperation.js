import { RegularFileOperationCancelled } from "../filesystem/RegularFile.js";
import { OwnedFileHandle } from "../filesystem/OwnedFileHandle.js";
import { withOwnedFileHandle, withOwnedRegularFile, RegularFileCancelled, RegularFileCleanupFailure, } from "../filesystem/OwnedRegularFile.js";
import { ArtifactReaderFailure, artifactPrimaryCleanupLeases, } from "./ArtifactReader.js";
import { AnalysisCleanupLease, AnalysisCleanupLeaseGroup, } from "./AnalysisCleanupLease.js";
/** Artifact projection plus the exact descriptor owner and physical operation outcome. */
export class ArtifactFileCleanupFailure extends ArtifactReaderFailure {
    cleanupLease;
    cleanupLeases;
    fileCleanupFailure;
    constructor(fileCleanupFailure, cleanupLease) {
        const outcome = fileCleanupFailure.outcome;
        if (outcome.kind === "failed" &&
            outcome.cause instanceof RegularFileOperationCancelled)
            fileCleanupFailure = new RegularFileCleanupFailure(fileCleanupFailure.path, fileCleanupFailure.owner, { kind: "failed", cause: artifactOperationCause(outcome.cause) }, fileCleanupFailure.cleanupCause, fileCleanupFailure.retention, fileCleanupFailure.completionCancellation);
        const completionCancellation = fileCleanupFailure.completionCancellation;
        const primary = fileCleanupFailure.outcome.kind === "failed"
            ? fileCleanupFailure.outcome.cause
            : completionCancellation === undefined
                ? fileCleanupFailure.cleanupCause
                : new ArtifactReaderFailure("cancelled", "Artifact read cancelled during close", {
                    cause: completionCancellation.reason,
                });
        const projected = ArtifactReaderFailure.withCleanup(primary, ArtifactReaderFailure.cleanupObservation(fileCleanupFailure.cleanupCause, fileCleanupFailure.path));
        super(projected.reason, projected.message, {
            cause: fileCleanupFailure,
            cleanup: projected.cleanup,
            partialObservation: projected.partialObservation,
            cancellation: projected.cancellation,
            ...(projected.boundary === undefined
                ? {}
                : { boundary: projected.boundary }),
        }, projected.details);
        this.cleanupLease = cleanupLease;
        this.fileCleanupFailure = fileCleanupFailure;
        const inherited = fileCleanupFailure.outcome.kind === "failed"
            ? artifactPrimaryCleanupLeases(fileCleanupFailure.outcome.cause)
            : [];
        this.cleanupLeases =
            inherited === undefined
                ? undefined
                : [...new Set([cleanupLease, ...inherited])];
    }
}
/** Normalize the physical primary failure without replacing its exact cleanup owner. */
export const mapArtifactFileFailure = (cause, classify) => {
    if (!(cause instanceof ArtifactFileCleanupFailure))
        return classify(cause);
    const physical = cause.fileCleanupFailure;
    if (physical.outcome.kind !== "failed")
        return cause;
    const primary = physical.outcome.cause instanceof ArtifactFileCleanupFailure
        ? mapArtifactFileFailure(physical.outcome.cause, classify)
        : classify(physical.outcome.cause);
    if (primary === physical.outcome.cause)
        return cause;
    return new ArtifactFileCleanupFailure(new RegularFileCleanupFailure(physical.path, physical.owner, { kind: "failed", cause: primary }, physical.cleanupCause, physical.retention, physical.completionCancellation), cause.cleanupLease);
};
/** Read only the physical outcomes carried by known nested file owners. */
export const artifactFilePrimaryFailure = (cause) => {
    while (cause instanceof ArtifactFileCleanupFailure &&
        cause.fileCleanupFailure.outcome.kind === "failed")
        cause = cause.fileCleanupFailure.outcome.cause;
    return cause;
};
/** Cancellation after confirmed close retains the completed physical operation. */
export class ArtifactFileCancelled extends ArtifactReaderFailure {
    fileCancellation;
    constructor(fileCancellation) {
        super("cancelled", "Artifact read cancelled", {
            cause: fileCancellation.reason,
        });
        this.fileCancellation = fileCancellation;
    }
}
/** Bind a translated failure to its exact descriptor leases, including failed retries. */
export const bindArtifactFileCleanup = (cause, error) => {
    const leases = cause instanceof ArtifactReaderFailure ? cause.cleanupLeases : undefined;
    if (leases !== undefined)
        new AnalysisCleanupLeaseGroup(error, leases);
};
/** Interpret this owner's typed cancellation, preserving an undefined reason. */
export const artifactFileCancellationCause = (cause) => {
    return cause.cancellation === undefined
        ? cause.cause
        : cause.cancellation.reason;
};
/** Report cancellation at the read stage that actually observed the caller signal. */
export const assertArtifactReadActive = (signal) => {
    if (signal?.aborted)
        throw new ArtifactReaderFailure("cancelled", "Artifact read cancelled", {
            cause: signal.reason,
        });
};
/** Admit a regular file without blocking on pipes, retaining failed admission closes. */
export const withArtifactRegularFile = async (path, resources, signal, operation, symlinks = "reject") => {
    let cleanupLease;
    assertArtifactReadActive(signal);
    try {
        const value = await withOwnedRegularFile(path, {
            symlinks,
            ...(signal === undefined ? {} : { signal }),
            retainFailedClose: (owner) => {
                cleanupLease = new AnalysisCleanupLease(() => owner.close(), [path]);
                resources.retain({
                    kind: "lease",
                    resource: path,
                    lease: cleanupLease,
                });
            },
        }, async (file) => {
            assertArtifactReadActive(signal);
            return await operation(file);
        });
        return value;
    }
    catch (cause) {
        if (cause instanceof RegularFileCleanupFailure &&
            cleanupLease !== undefined)
            throw new ArtifactFileCleanupFailure(cause, cleanupLease);
        if (cause instanceof RegularFileCancelled)
            throw new ArtifactFileCancelled(cause);
        throw artifactOperationCause(cause);
    }
};
/** Keep admission, operation outcome, final close and failed-owner transfer together. */
export const withArtifactFileHandle = async (path, file, resources, signal, operation) => {
    const owner = new OwnedFileHandle(file);
    const cleanupLease = new AnalysisCleanupLease(() => owner.close(), [path]);
    try {
        return await withOwnedFileHandle(path, owner, {
            ...(signal === undefined ? {} : { signal }),
            retainFailedClose: () => resources?.retain({
                kind: "lease",
                resource: path,
                lease: cleanupLease,
            }),
        }, operation);
    }
    catch (cause) {
        if (cause instanceof RegularFileCleanupFailure)
            throw new ArtifactFileCleanupFailure(cause, cleanupLease);
        if (cause instanceof RegularFileCancelled)
            throw new ArtifactFileCancelled(cause);
        throw artifactOperationCause(cause);
    }
};
const artifactOperationCause = (cause) => cause instanceof RegularFileOperationCancelled
    ? new ArtifactReaderFailure("cancelled", "Artifact file operation cancelled", { cause: cause.reason })
    : cause;
