import { assertArtifactReadActive } from "./ArtifactFileOperation.js";
import { lstat } from "node:fs/promises";
import { Readable } from "node:stream";
import { XcrunCommandRunner, } from "../native/CommandRunner.js";
import { parseLipoOutput, } from "../native/parsers/lipo.js";
import { machoCpuSubtypeBase } from "../domain/apple/machoCpuIdentity.js";
import { OwnedFileHandle } from "../filesystem/OwnedFileHandle.js";
import { readMachoImage } from "./apple/MachoLoadCommandReader.js";
import { ArtifactReaderFailure, copyArtifactEntry, sameArtifactEntry, } from "./ArtifactReader.js";
import { streamChunkToBuffer } from "./StreamBytes.js";
import { NonRegularFileReadError, RegularFileAdmissionFailure, openRegularFile, sameRegularFileState, } from "../filesystem/RegularFile.js";
import { readArtifactFileChunks } from "./readArtifactFileChunks.js";
/** Read-only universal Mach-O slice reader backed by native lipo metadata. */
export class MachOSliceArtifactReader {
    path;
    runner;
    format = "file";
    #command;
    #source;
    #ownedSource;
    #pendingSource;
    #entries = new Map();
    #pendingCommands = new Set();
    #ownsSource;
    #closed = false;
    #closePromise;
    constructor(path, environment, runner = new XcrunCommandRunner(environment), source) {
        this.path = path;
        this.runner = runner;
        this.#source = source;
        this.#ownsSource = source === undefined;
    }
    async *entries(signal) {
        this.#entries.clear();
        const source = await this.#ensureSource();
        await this.#verifySource(source);
        if (this.#closed)
            throw new ArtifactReaderFailure("unavailable", "Universal Mach-O reader is closed");
        const command = this.runner.run("lipo", ["-detailed_info", this.path], signal === undefined ? {} : { signal });
        this.#pendingCommands.add(command);
        let captured;
        try {
            captured = await command;
        }
        finally {
            this.#pendingCommands.delete(command);
        }
        if (!captured.ok)
            throw new ArtifactReaderFailure(captured.error.reason === "cancelled" ? "cancelled" : "unavailable", captured.error.detail === null
                ? "lipo could not enumerate universal Mach-O slices"
                : `lipo could not enumerate universal Mach-O slices: ${captured.error.detail}`, {
                cause: captured.error,
                ...(captured.error.cleanupFailure === null &&
                    captured.error.cleanupResources.length === 0
                    ? {}
                    : {
                        cleanup: {
                            reason: captured.error.cleanupFailure ??
                                "Native command cleanup remains unverified",
                            resources: [...captured.error.cleanupResources],
                        },
                    }),
            });
        if (this.#closed)
            throw new ArtifactReaderFailure("unavailable", "Universal Mach-O reader closed during slice discovery");
        this.#command = {
            tool: captured.value.tool,
            arguments: ["-detailed_info", "$ARTIFACT"],
            tool_version: captured.value.toolVersion,
            executable_sha256: captured.value.executableSha256,
            exit_code: captured.value.exitCode,
            effects: ["read"],
        };
        await this.#verifySource(source);
        const fileSize = source.initial.size;
        const { architectures } = parseLipoOutput(captured.value.stdout, this.path);
        const structural = await readStructuralSlices(source.handle, fileSize);
        await this.#verifySource(source);
        if (structural.status === "malformed")
            throw new ArtifactReaderFailure("integrity", `Mach-O structural slice index is malformed: ${structural.reason}`);
        // A valid universal binary can hold slices PhxRE cannot index, such as
        // big-endian PowerPC. lipo's own ranges still inventory every slice.
        if (structural.status === "unsupported" &&
            architectures.some(({ file_offset, size }) => file_offset === null || size === null))
            throw new ArtifactReaderFailure("unavailable", `Mach-O structural slice index is unsupported: ${structural.reason}`);
        const slices = structural.status === "parsed" ? structural.slices : null;
        const matchingSlices = new Map();
        if (slices !== null) {
            if (slices.length !== architectures.length)
                throw new ArtifactReaderFailure("integrity", "lipo architecture count disagrees with the Mach-O FAT table");
            const unmatched = [...slices];
            for (const reported of architectures) {
                const match = unmatched.findIndex((observed) => lipoMatchesSlice(reported, observed, slices.length === 1));
                if (match < 0)
                    throw new ArtifactReaderFailure("integrity", `lipo slice metadata disagrees with the Mach-O FAT table: ${reported.name} (cputype=${reported.cpu_type ?? "unknown"}, cpusubtype=${reported.cpu_subtype ?? "unknown"}, offset=${reported.file_offset ?? "unknown"}, size=${reported.size ?? "unknown"}, alignment=${reported.alignment ?? "unknown"})`);
                const [observed] = unmatched.splice(match, 1);
                if (observed !== undefined)
                    matchingSlices.set(reported, observed);
            }
        }
        for (const architecture of architectures) {
            const structuralSlice = matchingSlices.get(architecture);
            const offset = architecture.file_offset ?? structuralSlice?.slice_offset;
            const sliceSize = architecture.size ?? structuralSlice?.slice_size;
            if (offset === undefined || sliceSize === undefined)
                throw new ArtifactReaderFailure("integrity", "lipo omitted a universal slice byte range");
            if (!Number.isSafeInteger(offset) ||
                !Number.isSafeInteger(sliceSize) ||
                offset < 0 ||
                sliceSize <= 0 ||
                !Number.isSafeInteger(offset + sliceSize) ||
                offset + sliceSize > fileSize)
                throw new ArtifactReaderFailure("integrity", `lipo reported an out-of-bounds Mach-O slice: ${architecture.name}`);
            const entry = {
                path: `slices/${architecture.name}`,
                kind: "slice",
                declaredSize: sliceSize,
                compressedSize: null,
                executable: true,
                encrypted: false,
                byteOffset: offset,
                declaredIntegrity: null,
                unpacked: false,
                limitations: [
                    ...(structural.status === "not-mach-o"
                        ? [
                            "Structural Mach-O facts were unavailable; slice range is based on lipo output.",
                        ]
                        : structural.status === "unsupported"
                            ? [
                                `Structural Mach-O facts were unsupported (${structural.reason}); slice range is based on lipo output.`,
                            ]
                            : []),
                    ...(architecture.file_offset === null || architecture.size === null
                        ? [
                            "Slice range was derived from structural Mach-O facts because lipo omitted it.",
                        ]
                        : []),
                    ...(architecture.cpu_type !== null &&
                        architecture.cpu_type_code === null
                        ? [
                            `lipo CPU type is retained as unnormalized source text: ${architecture.cpu_type}`,
                        ]
                        : []),
                    ...(architecture.cpu_subtype !== null &&
                        architecture.cpu_subtype_code === null
                        ? [
                            `lipo CPU subtype is retained as unnormalized source text: ${architecture.cpu_subtype}${architecture.capabilities === null ? "" : `; capabilities ${architecture.capabilities}`}`,
                        ]
                        : []),
                ],
                adapterKey: `${String(offset)}:${String(sliceSize)}`,
            };
            this.#entries.set(entry.adapterKey, copyArtifactEntry(entry));
            yield entry;
        }
    }
    async open(entry, signal) {
        if (signal?.aborted === true)
            return Promise.reject(new ArtifactReaderFailure("cancelled", "Mach-O slice read cancelled", {
                cause: signal.reason,
            }));
        const produced = this.#entries.get(entry.adapterKey);
        if (produced === undefined || !sameArtifactEntry(entry, produced))
            throw new ArtifactReaderFailure("integrity", "Mach-O slice entry metadata does not match this reader's inventory");
        const offset = produced.byteOffset;
        const size = produced.declaredSize;
        if (offset === null ||
            size === null ||
            !Number.isSafeInteger(offset) ||
            !Number.isSafeInteger(size) ||
            offset < 0 ||
            size <= 0)
            throw new ArtifactReaderFailure("integrity", "Invalid Mach-O slice byte range");
        const source = await this.#ensureSource();
        await this.#verifySource(source);
        if (!Number.isSafeInteger(offset + size) ||
            offset + size > source.initial.size)
            throw new ArtifactReaderFailure("integrity", `Mach-O slice range is outside the artifact: ${entry.path}`);
        const sourceStream = readArtifactFileChunks(source.handle, {
            start: offset,
            end: offset + size - 1,
            ...(signal === undefined ? {} : { signal }),
        });
        const verifySource = () => this.#verifySource(source);
        let validatingSource = false;
        const completionFailure = () => {
            const coverage = sourceStream.readCoverage();
            if (coverage.kind !== "complete")
                return new ArtifactReaderFailure("integrity", `Mach-O slice read coverage is incomplete: ${entry.path}`);
            if (coverage.bytes !== BigInt(size))
                return new ArtifactReaderFailure("integrity", `Mach-O slice size disagrees with lipo metadata: ${entry.path}`);
            if (signal?.aborted)
                return new ArtifactReaderFailure("cancelled", "Mach-O slice read cancelled", { cause: signal.reason });
            return undefined;
        };
        const output = Readable.from((async function* () {
            try {
                for await (const raw of sourceStream) {
                    const chunk = streamChunkToBuffer(raw);
                    if (sourceStream.readCoverage().kind === "complete" &&
                        signal?.aborted) {
                        const failure = completionFailure();
                        if (failure !== undefined)
                            throw failure;
                    }
                    yield chunk;
                }
            }
            catch (cause) {
                if (cause instanceof ArtifactReaderFailure)
                    throw cause;
                throw new ArtifactReaderFailure("integrity", `Could not read Mach-O slice range: ${entry.path}`, { cause });
            }
            validatingSource = true;
            const failure = completionFailure();
            if (failure !== undefined)
                throw failure;
            try {
                await verifySource();
                assertArtifactReadActive(signal);
            }
            finally {
                validatingSource = false;
            }
        })());
        const onSourceError = (cause) => {
            const completedCancellation = cause instanceof ArtifactReaderFailure &&
                cause.reason === "cancelled" &&
                sourceStream.readCoverage().kind === "complete" &&
                !validatingSource
                ? completionFailure()
                : undefined;
            output.destroy(completedCancellation ??
                (cause instanceof ArtifactReaderFailure
                    ? cause
                    : new ArtifactReaderFailure("integrity", `Could not read Mach-O slice range: ${entry.path}`, { cause })));
        };
        sourceStream.on("error", onSourceError);
        sourceStream.once("close", () => sourceStream.removeListener("error", onSourceError));
        const onAbort = () => {
            if (sourceStream.readCoverage().kind === "complete" &&
                (sourceStream.errored === null ||
                    (sourceStream.errored instanceof ArtifactReaderFailure &&
                        sourceStream.errored.reason === "cancelled")) &&
                !validatingSource &&
                !output.destroyed) {
                const failure = completionFailure();
                if (failure !== undefined)
                    output.destroy(failure);
            }
        };
        signal?.addEventListener("abort", onAbort, { once: true });
        output.once("close", () => {
            signal?.removeEventListener("abort", onAbort);
            if (!sourceStream.destroyed)
                sourceStream.destroy();
        });
        if (signal?.aborted)
            onAbort();
        return output;
    }
    provenance() {
        return this.#command === undefined ? [] : [structuredClone(this.#command)];
    }
    async close() {
        this.#closed = true;
        this.#closePromise ??= this.#releaseResources().catch((cause) => {
            this.#closePromise = undefined;
            throw cause;
        });
        return this.#closePromise;
    }
    async #releaseResources() {
        await Promise.allSettled(this.#pendingCommands);
        let cleanup;
        try {
            const failures = (await this.runner.retryCleanup?.()) ?? [];
            if (failures.length > 0)
                cleanup = {
                    reason: failures
                        .map(({ reason, resources }) => `${resources.join(", ")}: ${reason}`)
                        .join("; "),
                    resources: [
                        ...new Set(failures.flatMap(({ resources }) => resources)),
                    ],
                };
        }
        catch (cause) {
            cleanup = ArtifactReaderFailure.cleanupObservation(cause, "native-command-process-cleanup");
        }
        try {
            await this.#closeSource();
        }
        catch (cause) {
            if (cleanup === undefined)
                throw cause;
            throw ArtifactReaderFailure.withCleanup(cause, cleanup);
        }
        if (cleanup !== undefined)
            throw new ArtifactReaderFailure("unavailable", "Native command process cleanup remains incomplete", { cleanup });
    }
    async #ensureSource() {
        if (this.#closed)
            throw new ArtifactReaderFailure("unavailable", "Universal Mach-O reader is closed");
        if (this.#source !== undefined)
            return this.#source;
        this.#pendingSource ??= this.#acquireSource();
        const source = await this.#pendingSource;
        if (this.#closed)
            throw new ArtifactReaderFailure("unavailable", "Universal Mach-O reader closed during source acquisition");
        return source;
    }
    async #acquireSource() {
        let handle;
        try {
            handle = await openRegularFile(this.path, { symlinks: "reject" });
        }
        catch (cause) {
            if (!(cause instanceof RegularFileAdmissionFailure))
                throw cause;
            this.#ownedSource = cause.owner;
            const primary = cause.cause instanceof NonRegularFileReadError
                ? new ArtifactReaderFailure("format", `Universal Mach-O source is not a regular file: ${this.path}`, { cause: cause.cause })
                : cause.cause;
            throw ArtifactReaderFailure.withCleanup(primary, ArtifactReaderFailure.cleanupObservation(cause.cleanupCause, this.path));
        }
        const owner = new OwnedFileHandle(handle);
        this.#ownedSource = owner;
        try {
            const initial = await handle.stat();
            const source = { handle, initial };
            this.#source = source;
            return source;
        }
        catch (cause) {
            try {
                await owner.close();
                this.#ownedSource = undefined;
            }
            catch (cleanupCause) {
                throw ArtifactReaderFailure.withCleanup(cause, ArtifactReaderFailure.cleanupObservation(cleanupCause, this.path));
            }
            throw cause;
        }
    }
    async #closeSource() {
        await this.#pendingSource?.catch(() => undefined);
        if (!this.#ownsSource || this.#ownedSource === undefined)
            return;
        await this.#ownedSource.close();
        this.#ownedSource = undefined;
        this.#source = undefined;
    }
    async #verifySource(source) {
        const [opened, currentPath] = await Promise.all([
            source.handle.stat(),
            lstat(this.path),
        ]);
        if (!sameRegularFileState(source.initial, opened) ||
            !sameRegularFileState(source.initial, currentPath))
            throw new ArtifactReaderFailure("integrity", `Universal Mach-O source changed during inventory: ${this.path}`);
    }
}
/** Compare lipo's independent ranges with structurally parsed slice identity. */
const readStructuralSlices = async (file, size) => {
    const readAt = async (offset, length) => {
        const bytes = Buffer.alloc(length);
        const { bytesRead } = await file.read(bytes, 0, length, offset);
        return bytes.subarray(0, bytesRead);
    };
    return readMachoImage(readAt, size);
};
const lipoMatchesSlice = (reported, observed, structurallyUnique) => {
    const observedCpuType = observed.fat_cpu_type ?? observed.cpu_type;
    const observedCpuSubtype = observed.fat_cpu_subtype ?? observed.cpu_subtype;
    const hasPhysicalIdentity = reported.file_offset !== null ||
        reported.size !== null ||
        reported.cpu_type_code !== null ||
        reported.cpu_subtype_code !== null;
    return ((hasPhysicalIdentity || structurallyUnique) &&
        lipoNameMatches(reported.name, observed.architecture) &&
        (reported.file_offset === null ||
            reported.file_offset === observed.slice_offset) &&
        (reported.size === null || reported.size === observed.slice_size) &&
        (reported.cpu_type_code === null ||
            reported.cpu_type_code === observedCpuType) &&
        lipoSubtypeMatches(reported, observedCpuSubtype) &&
        (reported.alignment === null ||
            observed.fat_alignment_exponent === null ||
            reported.alignment === 2 ** observed.fat_alignment_exponent));
};
/**
 * Compare the complete subtype when lipo printed its capability byte, and
 * otherwise only the subtype bits its record names.
 */
const lipoSubtypeMatches = (reported, observedCpuSubtype) => {
    if (reported.cpu_subtype_code !== null)
        return reported.cpu_subtype_code === observedCpuSubtype;
    return (reported.cpu_subtype_base === null ||
        reported.cpu_subtype_base === machoCpuSubtypeBase(observedCpuSubtype));
};
/**
 * Newer lipo names an arm64e ABI variant `arm64e.<variant>` (for example
 * `arm64e.v1` for pointer-auth ABI version 1). The FAT table names that slice
 * `arm64e`; its physical identity is still compared field by field.
 */
const lipoNameMatches = (reported, observed) => reported === observed ||
    (observed === "arm64e" && /^arm64e\.[A-Za-z0-9_]+$/u.test(reported));
