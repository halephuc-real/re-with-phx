import { locateGodotPck } from "../GodotPckLocation.js";
import { withArtifactRegularFile } from "../ArtifactFileOperation.js";
import { lstat, realpath } from "node:fs/promises";
import { compareUnicodeCodePoints } from "../../domain/unicodeCodePointOrder.js";
import { digestCanonicalValue } from "../../domain/canonicalDigest.js";
import { AsarArtifactReader } from "../AsarArtifactReader.js";
import { GodotPckArtifactReader } from "../GodotPckArtifactReader.js";
import { ArtifactPathRegistry, normalizeArtifactPath, } from "../ArtifactPaths.js";
import { ArtifactReaderFailure, } from "../ArtifactReader.js";
import { abortIfNeeded } from "../ArtifactHash.js";
import { DirectoryArtifactReader } from "../DirectoryArtifactReader.js";
import { SafeOutputTree } from "../SafeOutputTree.js";
import { SafeOutputTreeCreationFailure } from "../SafeOutputTreeCreationFailure.js";
import { ZipArtifactReader } from "../ZipArtifactReader.js";
import { isZipPackageFormat } from "../../domain/zipPackageFormat.js";
import { MachOSliceArtifactReader } from "../MachOSliceArtifactReader.js";
import { PyInstallerArtifactReader } from "../PyInstallerArtifactReader.js";
import { containsPyInstallerArchive } from "../pyinstaller/CArchiveLayout.js";
import { artifactExtractionResultSchema, } from "../../domain/artifactGraph.js";
import { AnalysisUnsupportedTargetError } from "../../domain/analysisErrorCore.js";
import { isMachOFormat, } from "../../domain/binaryTargetTypes.js";
import { scanArtifactInventoryInScope } from "../inventory/ArtifactInventory.js";
/** Extract every regular inventory occurrence into an exclusively owned absent root. */
export const extractArtifact = async (input, signal) => input.resourceScope.run(() => extractArtifactInScope(input, signal));
const extractArtifactInScope = async (input, signal) => {
    // Cancellation wins over every later refusal, including unsupported formats.
    abortIfNeeded(signal);
    const sourcePath = await realpath(input.inputPath);
    await requireExtractableFormat(sourcePath, input, signal);
    const snapshot = await scanArtifactInventoryInScope(sourcePath, {
        resourceScope: input.resourceScope,
        signal,
        environment: input.environment,
        integrity: { mode: input.integrityPolicy },
    });
    return materializeArtifactInventoryInScope(input, sourcePath, snapshot, signal);
};
/** Materialize a scanned inventory, verifying every current occurrence against it. */
export const materializeArtifactInventory = async (input, sourcePath, snapshot, signal) => {
    return input.resourceScope.run(() => materializeArtifactInventoryInScope(input, sourcePath, snapshot, signal));
};
const materializeArtifactInventoryInScope = async (input, sourcePath, snapshot, signal) => {
    abortIfNeeded(signal);
    const containerMetadata = snapshot.occurrences.find((row) => row.logical_path === ".")?.format_metadata;
    if (containerMetadata?.kind === "godot-pck" &&
        containerMetadata.directory_status !== "available")
        throw new AnalysisUnsupportedTargetError("extract_artifact", input.inputPath, `Godot PCK directory is ${containerMetadata.directory_status}; its complete contents cannot be extracted`);
    const selectedOccurrences = snapshot.occurrences.filter((occurrence) => (occurrence.entry_kind === "file" || occurrence.entry_kind === "slice") &&
        occurrence.logical_path !== ".");
    const regularPaths = new Set(selectedOccurrences.map(({ logical_path: path }) => path));
    const activeOccurrences = selectedOccurrences.filter(({ logical_path }) => {
        // Nested members remain represented by their containing regular file;
        // only entries exposed by the active reader are materialized.
        let path = logical_path;
        for (let slash = path.lastIndexOf("/"); slash >= 0; slash = path.lastIndexOf("/")) {
            path = path.slice(0, slash);
            if (regularPaths.has(path))
                return false;
        }
        return true;
    });
    const selectedIds = new Set(activeOccurrences.map(({ occurrence_id: id }) => id));
    const neededNodes = new Set(activeOccurrences.map(({ artifact_id: id }) => id));
    const nodes = new Map();
    for (const node of snapshot.nodes)
        if (neededNodes.has(node.artifact_id))
            nodes.set(node.artifact_id, node);
    const inventory = {
        manifest: snapshot.manifest,
        integrityContradictions: snapshot.integrity_contradictions.filter(({ occurrence_id: id }) => selectedIds.has(id)),
    };
    const selected = activeOccurrences.map((occurrence) => {
        // PhxRE never decrypts archive entries, so an encrypted entry makes the
        // complete extraction unsupported rather than the archive invalid.
        if (occurrence.encrypted)
            throw new AnalysisUnsupportedTargetError("extract_artifact", input.inputPath, `Archive entry ${occurrence.logical_path} is encrypted; PhxRE does not decrypt archive entries, so the archive cannot be extracted completely`);
        // Inventory keeps an ASAR unpacked entry whose companion file is absent,
        // but extraction cannot materialize bytes it never observed.
        if (occurrence.entry_kind === "file" &&
            occurrence.artifact_id === null &&
            occurrence.hash_status === "unavailable")
            throw new ArtifactReaderFailure("unavailable", `ASAR unpacked companion bytes are unavailable for ${occurrence.logical_path}`, undefined, {
                logicalPath: occurrence.logical_path,
                declaredSha256: null,
                calculatedSha256: null,
                unpacked: true,
            });
        if ((occurrence.entry_kind !== "file" && occurrence.entry_kind !== "slice") ||
            occurrence.artifact_id === null ||
            occurrence.logical_path === ".")
            throw new ArtifactReaderFailure("format", `Selected occurrence is not an extractable regular child file: ${occurrence.logical_path} (${occurrence.occurrence_id})`);
        const node = nodes.get(occurrence.artifact_id);
        if (node === undefined)
            throw new ArtifactReaderFailure("integrity", `Selected occurrence has no inventory node: ${occurrence.occurrence_id}`);
        return { occurrence, node };
    });
    return materializeSelection({
        input,
        sourcePath,
        inventory,
        selected,
        signal,
    });
};
const materializeSelection = async ({ input, sourcePath, inventory, selected, signal, }) => {
    const byPath = new Map();
    for (const item of selected) {
        const path = item.occurrence.logical_path;
        if (byPath.has(path))
            throw new ArtifactReaderFailure("path", `Artifact extraction path collision: ${JSON.stringify(path)}. Multiple selected occurrences share this normalized logical path; they cannot be materialized at the same destination path, even when the archive is valid. Inventory retains each occurrence.`);
        byPath.set(path, item);
    }
    const reader = await createReader(sourcePath, input, inventory.manifest.root_format, signal);
    const readerOwner = {
        kind: "reader",
        reader,
        resource: `artifact reader for ${sourcePath}`,
    };
    let localReaderOwner = readerOwner;
    let output;
    let completed;
    const extracted = [];
    try {
        await reader.prepareContainer?.(inventory.manifest.root_sha256, signal);
        try {
            output = await SafeOutputTree.create(input.outputRoot);
        }
        catch (cause) {
            if (cause instanceof SafeOutputTreeCreationFailure)
                output = cause.tree;
            throw cause;
        }
        await writeSelectedEntries({ reader, output, byPath, extracted, signal });
        localReaderOwner = undefined;
        const closeAttempt = await input.resourceScope.release(readerOwner);
        if (closeAttempt.kind === "failed")
            throw input.resourceScope.cleanupFailure({ kind: "completed" }, [
                closeAttempt,
            ]);
        extracted.sort((left, right) => compareUnicodeCodePoints(left.relative_path, right.relative_path));
        completed = createExtractionResult(input, inventory, selected, extracted);
        await output.commit(signal);
        return completed;
    }
    catch (cause) {
        const cleanupFailures = await releaseExtractionOwners(input.resourceScope, localReaderOwner, output, input.outputRoot);
        const [firstCleanup, ...remainingCleanup] = cleanupFailures;
        if (firstCleanup !== undefined) {
            throw input.resourceScope.cleanupFailure({ kind: "failed", cause }, [firstCleanup, ...remainingCleanup], output?.published === true && completed !== undefined
                ? { kind: "artifact-extraction", extraction: completed }
                : undefined);
        }
        if (output?.published === true && completed !== undefined)
            return completed;
        throw cause;
    }
};
const writeSelectedEntries = async ({ reader, output, byPath, extracted, signal, }) => {
    const registry = new ArtifactPathRegistry();
    for await (const entry of reader.entries(signal)) {
        const path = normalizeArtifactPath(entry.path);
        registry.add(path, entry.kind);
        // Logical declarations may share a query path with a real file. They do
        // not consume that file's selection or participate in materialization.
        if (entry.kind !== "file" && entry.kind !== "slice")
            continue;
        const selectedItem = byPath.get(path);
        if (selectedItem === undefined) {
            throw new ArtifactReaderFailure("integrity", `Regular artifact entry is missing from inventory: ${path}`);
        }
        preflight(entry);
        const stream = await reader.open(entry, signal);
        const written = await output.write(path, stream, {
            sha256: selectedItem.node.sha256,
            bytes: selectedItem.node.size,
        }, signal);
        extracted.push({
            artifact_id: selectedItem.node.artifact_id,
            relative_path: written.relativePath,
            sha256: written.sha256,
            bytes_written: written.bytesWritten,
            created: true,
        });
        byPath.delete(path);
    }
    if (byPath.size > 0)
        throw new ArtifactReaderFailure("integrity", `Inventoried regular artifact entries were not materialized: ${[...byPath.keys()].sort(compareUnicodeCodePoints).join(", ")}`);
};
const releaseExtractionOwners = async (resourceScope, readerOwner, output, outputRoot) => {
    const failures = [];
    if (readerOwner !== undefined) {
        const attempt = await resourceScope.release(readerOwner);
        if (attempt.kind === "failed")
            failures.push(attempt);
    }
    if (output !== undefined) {
        const owner = {
            kind: "output-tree",
            tree: output,
            resource: outputRoot,
        };
        const attempt = await resourceScope.release(owner);
        if (attempt.kind === "failed")
            failures.push(attempt);
    }
    return failures;
};
const createExtractionResult = (input, inventory, selected, extracted) => {
    const extractionSemantic = {
        source_manifest_id: inventory.manifest.manifest_id,
        selected_occurrence_ids: selected
            .map(({ occurrence }) => occurrence.occurrence_id)
            .sort(compareUnicodeCodePoints),
        files_sha256: digestCanonicalValue(extracted, "Artifact"),
        output_root_alias: "$OUTPUT_ROOT",
    };
    return artifactExtractionResultSchema.parse({
        manifest: inventory.manifest,
        extraction_manifest: {
            ...extractionSemantic,
            extraction_id: `aex_${digestCanonicalValue(extractionSemantic, "Artifact")}`,
        },
        output_root: input.outputRoot,
        artifacts: extracted,
        containment_verified: true,
        cleanup: { attempted: false, verified: true, residual_paths: [] },
        provenance: [],
        integrity_contradictions: inventory.integrityContradictions,
        limitations: [
            "All regular files in the active artifact were materialized; nested archive contents remain represented by their containing file.",
            ...(inventory.integrityContradictions.length === 0
                ? []
                : [
                    `${String(inventory.integrityContradictions.length)} extracted file(s) contradict declared integrity metadata; their bytes are observed-untrusted.`,
                ]),
        ],
    });
};
/**
 * Refuse a format without an extraction reader before inventory work starts.
 * The target kind, not the host, is unsupported by extraction. The error keeps
 * the caller's spelling of the path; I/O uses the canonical path.
 */
const requireExtractableFormat = async (path, input, signal) => {
    const format = input.inputFormat;
    const directory = (await lstat(path)).isDirectory();
    if (!directory &&
        format !== "asar" &&
        format !== "godot-pck" &&
        !isMachOFormat(format) &&
        !isZipPackageFormat(format)) {
        const pack = await withArtifactRegularFile(path, input.resourceScope, signal, async (handle) => {
            const size = (await handle.stat()).size;
            if (await locateGodotPck(handle, size, signal))
                return true;
            if (format !== "elf" && format !== "pe")
                return false;
            abortIfNeeded(signal);
            const packaged = await containsPyInstallerArchive(handle, size, signal);
            abortIfNeeded(signal);
            return packaged;
        });
        if (!pack)
            throw new AnalysisUnsupportedTargetError("extract_artifact", input.inputPath, `Artifact format has no extraction reader: ${format}`);
    }
    return directory;
};
const createReader = async (path, input, containerFormat, signal) => {
    const format = input.inputFormat;
    if (containerFormat === "godot-pck")
        return new GodotPckArtifactReader(path);
    if (containerFormat === "pyinstaller")
        return new PyInstallerArtifactReader(path);
    if (await requireExtractableFormat(path, input, signal))
        return new DirectoryArtifactReader(path);
    if (format === "asar")
        return new AsarArtifactReader(path);
    if (isZipPackageFormat(format))
        return new ZipArtifactReader(path, format);
    return new MachOSliceArtifactReader(path, input.environment);
};
const preflight = (entry) => {
    if ((entry.kind !== "file" && entry.kind !== "slice") || entry.encrypted)
        throw new ArtifactReaderFailure("format", `Selected artifact entry cannot be read: ${entry.path}`);
};
