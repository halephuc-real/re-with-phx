import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createInflate } from "node:zlib";
import { ArtifactReaderFailure } from "../ArtifactReader.js";
import { abortIfNeeded } from "../ArtifactHash.js";
/** Backpressure bounds plaintext independently of the untrusted declared size. */
export const pyInstallerMemberStream = (source, options) => {
    let bytes = 0;
    let headerSent = false;
    let completing = false;
    const prependHeader = () => {
        if (!headerSent && options.header !== undefined)
            output.push(options.header);
        headerSent = true;
    };
    const output = new Transform({
        transform(chunk, _encoding, callback) {
            try {
                abortIfNeeded(options.signal);
                bytes += chunk.length;
                if (bytes > options.maxBytes)
                    throw new ArtifactReaderFailure("limit", "PyInstaller member exceeds its plaintext budget");
                options.charge?.(chunk.length);
                prependHeader();
                callback(null, chunk);
            }
            catch (cause) {
                callback(asError(cause));
            }
        },
        flush(callback) {
            completing = true;
            void (async () => {
                abortIfNeeded(options.signal);
                if (inflate !== undefined &&
                    inflate.bytesWritten !== options.sourceBytes)
                    throw new ArtifactReaderFailure("integrity", "Compressed PyInstaller member did not consume its complete declared source span");
                if (options.expectedBytes !== undefined &&
                    bytes !== options.expectedBytes)
                    throw new ArtifactReaderFailure("integrity", "PyInstaller member size disagrees with its declaration or previous observation");
                await options.complete?.(bytes);
                abortIfNeeded(options.signal);
                prependHeader();
            })().then(() => {
                completing = false;
                try {
                    abortIfNeeded(options.signal);
                }
                catch (cause) {
                    callback(asError(cause));
                    return;
                }
                callback();
            }, (cause) => {
                completing = false;
                callback(asError(cause));
            });
        },
    });
    // A consumer can retire its reader before attaching its stream error handler.
    output.on("error", () => undefined);
    const onAbort = () => {
        // Verification and private-file cleanup own their accepted native I/O.
        if (completing)
            return;
        // The descriptor source owns cancellation until its native read settles.
        // Retiring it downstream earlier would hide a native I/O rejection.
        if (!source.readableEnded && !source.destroyed)
            return;
        output.destroy(new ArtifactReaderFailure("cancelled", "PyInstaller member read cancelled", { cause: options.signal.reason }));
    };
    options.signal.addEventListener("abort", onAbort, { once: true });
    const onSourceFailure = (cause) => {
        output.destroy(cause instanceof ArtifactReaderFailure
            ? cause
            : new ArtifactReaderFailure("io", "PyInstaller member source could not be read", { cause }));
    };
    source.on("error", onSourceFailure);
    const inflate = options.compressed ? createInflate() : undefined;
    inflate?.on("error", (cause) => output.destroy(new ArtifactReaderFailure("format", "Compressed PyInstaller member is not a complete zlib stream", { cause })));
    const completion = (inflate === undefined
        ? pipeline(source, output)
        : pipeline(source, inflate, output)).finally(() => {
        options.signal.removeEventListener("abort", onAbort);
        source.removeListener("error", onSourceFailure);
    });
    // Preserve rejection for the owning scope without an early unhandled promise.
    void completion.catch(() => undefined);
    if (options.signal.aborted)
        onAbort();
    return { output, completion };
};
const asError = (cause) => cause instanceof Error
    ? cause
    : new ArtifactReaderFailure("format", "PyInstaller member read failed", {
        cause,
    });
