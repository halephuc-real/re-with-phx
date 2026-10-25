import fs from "node:fs";
import { lstat } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { err, ok } from "../domain/result.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { readRegularFile, RegularFileCleanupFailure, retryRegularFileCleanup, } from "./RegularFileRead.js";
/**
 * Read Git metadata for a directory using isomorphic-git.
 *
 * No git subprocess or network is used; only the local `.git` object store is read.
 */
export const readReferenceSourceVcs = async (root, resources, signal) => {
    try {
        return await resources.run(async () => {
            // Like Git, a subdirectory belongs to its nearest enclosing repository;
            // only a missing `.git` at every ancestor means no version control.
            let repository = resolve(root);
            for (;;) {
                if (isAborted(signal))
                    return ok(unknownVcs());
                try {
                    await lstat(join(repository, ".git"));
                    break;
                }
                catch (cause) {
                    if (errorCode(cause) !== "ENOENT")
                        return ok(unknownVcs());
                }
                const parent = dirname(repository);
                if (parent === repository)
                    return ok({ kind: "none", head: null, dirty: null });
                repository = parent;
            }
            try {
                const head = await resolveSourceHead(repository, resources, signal);
                if (isAborted(signal))
                    return ok(unknownVcs());
                return ok({ kind: "git", head, dirty: null });
            }
            catch (cause) {
                if (cause instanceof ArtifactReaderFailure)
                    throw cause;
                return ok(unknownVcs());
            }
        });
    }
    catch (cause) {
        if (!(cause instanceof ArtifactReaderFailure))
            throw cause;
        return err({
            tag: "reference-source-reader",
            code: cause.reason === "cancelled" ? "cancelled" : "io",
            message: cause.message,
            ...(cause.cleanup === undefined ? {} : { cleanup: cause.cleanup }),
            cause,
        });
    }
};
const unknownVcs = () => ({
    kind: "unknown",
    head: null,
    dirty: null,
});
const resolveSourceHead = async (root, resources, signal) => {
    // isomorphic-git is loaded on first use so CLI and MCP startup skip it.
    const { resolveRef } = await import("isomorphic-git");
    let failedRead;
    const cleanupFailures = [];
    const readMetadataBytes = async (path) => {
        try {
            return await readRegularFile(path, { signal });
        }
        catch (cause) {
            if (signal?.aborted === true && cause === signal.reason)
                throw cause;
            if (!(cause instanceof RegularFileCleanupFailure))
                throw cause;
            const retry = await retryRegularFileCleanup(cause, resources, signal);
            if (retry.outcome.kind === "failed" &&
                errorCode(retry.outcome.cause) !== "ENOENT")
                failedRead ??= { cause: retry.outcome.cause };
            if (retry.cleanup === undefined &&
                retry.outcome.kind === "failed" &&
                !isAborted(signal))
                throw retry.outcome.cause;
            const primary = retry.outcome.kind === "failed"
                ? retry.outcome.cause
                : cause.cleanupCause;
            throw new ArtifactReaderFailure(isAborted(signal) ? "cancelled" : "io", `Git metadata could not be read safely: ${errorMessage(primary)}`, {
                cause: primary,
                ...(retry.cleanup === undefined ? {} : { cleanup: retry.cleanup }),
            });
        }
    };
    const readMetadataText = async (path) => (await readMetadataBytes(path)).toString("utf8");
    const throwCleanupFailures = (primary) => {
        const observations = cleanupFailures.flatMap((failure) => failure.cleanup === undefined ? [] : [failure.cleanup]);
        throw new ArtifactReaderFailure(isAborted(signal) ? "cancelled" : "io", `Git metadata could not be read safely: ${errorMessage(primary)}`, {
            cause: new AggregateError([primary, ...cleanupFailures], "Git metadata reads and cleanup failed", { cause: primary }),
            ...(observations.length === 0
                ? {}
                : {
                    cleanup: {
                        reason: observations.map(({ reason }) => reason).join("; "),
                        resources: [
                            ...new Set(observations.flatMap(({ resources }) => resources)),
                        ],
                    },
                }),
        });
    };
    const referenceFs = {
        ...fs,
        promises: {
            ...fs.promises,
            // Let isomorphic-git continue from a failed loose ref to packed-refs,
            // then report the original read failure after resolution. This preserves
            // both observations when packed metadata also fails cleanup.
            readFile: async (path, options = null) => {
                // The library probes readFile() without a path to detect promise APIs.
                // Reject that invocation without attributing it to a source read.
                if (path === undefined)
                    throw new TypeError("Git metadata path is required");
                try {
                    const bytes = await readMetadataBytes(path);
                    const encoding = typeof options === "string"
                        ? options
                        : typeof options === "object" &&
                            options !== null &&
                            "encoding" in options
                            ? options.encoding
                            : undefined;
                    if (encoding === undefined || encoding === null)
                        return bytes;
                    if (typeof encoding !== "string" || !Buffer.isEncoding(encoding))
                        throw new TypeError("Unsupported Git metadata text encoding");
                    return bytes.toString(encoding);
                }
                catch (cause) {
                    if (cause instanceof ArtifactReaderFailure) {
                        cleanupFailures.push(cause);
                    }
                    else if (errorCode(cause) !== "ENOENT")
                        failedRead ??= { cause };
                    throw cause;
                }
            },
        },
    };
    const readRef = async (options) => {
        let head;
        try {
            head = await resolveRef({ fs: referenceFs, dir: root, ...options });
        }
        catch (cause) {
            if (cleanupFailures.length > 0)
                throwCleanupFailures(failedRead?.cause ?? cause);
            if (failedRead !== undefined)
                throw failedRead.cause;
            throw cause;
        }
        if (cleanupFailures.length > 0)
            throwCleanupFailures(failedRead?.cause ?? cleanupFailures[0]?.cause);
        signal?.throwIfAborted();
        if (failedRead !== undefined)
            throw failedRead.cause;
        return head;
    };
    const dotgit = join(root, ".git");
    if (!(await lstat(dotgit)).isFile())
        return readRef({ ref: "HEAD" });
    const pointer = (await readMetadataText(dotgit)).replace(/\r?\n$/u, "");
    if (!pointer.startsWith("gitdir: ") || pointer.length === 8)
        throw new Error("Invalid Git directory pointer");
    const gitdir = resolve(root, pointer.slice(8));
    let commonDirectory;
    try {
        commonDirectory = resolve(gitdir, (await readMetadataText(join(gitdir, "commondir"))).replace(/\r?\n$/u, ""));
    }
    catch (cause) {
        if (errorCode(cause) !== "ENOENT")
            throw cause;
        return readRef({ gitdir, ref: "HEAD" });
    }
    const head = (await readMetadataText(join(gitdir, "HEAD"))).trim();
    if (!head.startsWith("ref: "))
        return readRef({ gitdir, ref: "HEAD" });
    const ref = head.slice(5);
    const privateRef = ["refs/bisect/", "refs/rewritten/", "refs/worktree/"].some((prefix) => ref.startsWith(prefix));
    return readRef({
        gitdir: privateRef ? gitdir : commonDirectory,
        ref,
    });
};
const errorCode = (cause) => typeof cause === "object" && cause !== null && "code" in cause
    ? String(cause.code)
    : undefined;
const errorMessage = (cause) => cause instanceof Error ? cause.message : String(cause);
const isAborted = (signal) => signal?.aborted === true;
