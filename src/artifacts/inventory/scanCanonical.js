import { compareUnicodeCodePoints } from "../../domain/unicodeCodePointOrder.js";
import { AsarArtifactReader } from "../AsarArtifactReader.js";
import { lstat } from "node:fs/promises";
import { ArtifactReaderFailure, } from "../ArtifactReader.js";
import { artifactInventoryResultSchema, } from "../../domain/artifactGraph.js";
import { createArtifactEdges, createRootNode, materializeDirectoryNodes, rekeyOccurrences, rootOccurrenceFor, } from "./ArtifactGraphConstruction.js";
import { artifactContradictionId, artifactGraphDigest, artifactManifestId, } from "../../domain/artifactIdentity.js";
import { classifyAndHashRootForInventory } from "./classify.js";
import { hostExecutableMarking } from "../hostExecutableMarking.js";
import { hashStableRootArtifact, hashStableRootArtifactHandle, } from "./hashStableRootArtifact.js";
import { createReader, inventoryCoverage } from "./reader.js";
import { scanReader, } from "./scanReader.js";
import { STRICT_INTEGRITY_POLICY, } from "./types.js";
export const scanCanonicalArtifactInventory = async (path, options, readerFactory = createReader) => options.resourceScope.run(() => scanCanonicalArtifactInventoryInScope(path, options, readerFactory));
export const scanCanonicalArtifactInventoryInScope = async (path, options, readerFactory = createReader) => {
    const integrity = options.integrity ?? STRICT_INTEGRITY_POLICY;
    const metadata = await lstat(path);
    const { format: rootFormat, digest: rootDigest, rootSource, } = await classifyAndHashRootForInventory(path, metadata.isDirectory(), metadata, options);
    let reader;
    let readerCreationFailure;
    try {
        reader = readerFactory(path, rootFormat, options.environment ?? {}, rootSource);
    }
    catch (cause) {
        readerCreationFailure = { cause };
    }
    const ownedReaders = reader === undefined ? [] : [reader];
    let outcome;
    try {
        if (readerCreationFailure !== undefined)
            throw readerCreationFailure.cause;
        if (reader instanceof AsarArtifactReader)
            await reader.prepareContainer(rootDigest?.sha256, options.signal);
        const { nodes, occurrences, pendingContradictions, caseCollisionLimitation, unknownParentOccurrences, traversal, } = await scanReader(reader, ownedReaders, options.signal, integrity);
        outcome = {
            kind: "completed",
            snapshot: await buildInventorySnapshot({
                path,
                metadata,
                rootFormat,
                rootDigest,
                rootSource,
                resourceScope: options.resourceScope,
                reader,
                signal: options.signal,
                nodes,
                occurrences,
                pendingContradictions,
                caseCollisionLimitation,
                unknownParentOccurrences,
                traversal,
            }),
        };
    }
    catch (cause) {
        outcome = { kind: "failed", cause };
    }
    const cleanupFailure = await cleanupInventoryOwners({
        path,
        options,
        rootSource,
        ownedReaders,
        outcome,
    });
    if (cleanupFailure !== undefined)
        throw cleanupFailure;
    if (outcome.kind === "failed")
        throw outcome.cause;
    return outcome.snapshot;
};
const cleanupInventoryOwners = async ({ path, options, rootSource, ownedReaders, outcome, }) => {
    let cleanupFailure;
    const owners = [...ownedReaders]
        .reverse()
        .map((reader) => ({
        kind: "reader",
        reader,
        resource: `artifact reader for ${path}`,
    }));
    if (rootSource !== undefined)
        owners.push({
            kind: "file-handle",
            handle: rootSource.owner,
            resource: `root artifact descriptor for ${path}`,
        });
    for (const owner of owners) {
        const attempt = await options.resourceScope.release(owner);
        if (attempt.kind === "released")
            continue;
        cleanupFailure = options.resourceScope.cleanupFailure(cleanupFailure === undefined
            ? outcome
            : { kind: "failed", cause: cleanupFailure }, [attempt], outcome.kind === "completed"
            ? { kind: "artifact-inventory", inventory: outcome.snapshot }
            : undefined);
    }
    return cleanupFailure;
};
const buildInventorySnapshot = async (input) => {
    const { path, metadata, rootFormat, rootDigest, rootSource, reader, signal } = input;
    materializeDirectoryNodes(input.occurrences, input.nodes);
    const rootNode = createRootNode({
        digest: rootDigest,
        occurrences: input.occurrences,
    });
    input.nodes.set(rootNode.artifact_id, rootNode);
    rekeyOccurrences(rootNode.artifact_id, input.occurrences);
    const rootOccurrence = rootOccurrenceFor(rootNode, {
        size: metadata.size,
        executable: hostExecutableMarking(path, metadata),
        format: rootFormat,
        path,
        formatMetadata: reader?.formatMetadata?.(),
    });
    for (const occurrence of input.occurrences)
        if (occurrence.parent_occurrence_id === null &&
            !input.unknownParentOccurrences.has(occurrence))
            occurrence.parent_occurrence_id = rootOccurrence.occurrence_id;
    input.occurrences.unshift(rootOccurrence);
    const occurrenceById = new Map(input.occurrences.map((occurrence) => [
        occurrence.occurrence_id,
        occurrence,
    ]));
    const integrityContradictions = buildIntegrityContradictions(input.pendingContradictions, occurrenceById, rootNode);
    const edgeResult = createArtifactEdges(rootNode.artifact_id, input.occurrences, reader?.provenance()[0]);
    const { edges } = edgeResult;
    const orderedNodes = sortNodes([...input.nodes.values()]);
    const orderedOccurrences = sortOccurrences(input.occurrences);
    const orderedEdges = sortEdges(edges).map((edge, ordinal) => ({
        ...edge,
        ordinal,
    }));
    await verifyRootDigest(path, rootDigest, rootSource, input.resourceScope, signal);
    const graphSha256 = artifactGraphDigest({
        nodes: orderedNodes,
        occurrences: orderedOccurrences,
        edges: orderedEdges,
        contradictions: integrityContradictions,
    });
    const manifest = buildManifest({
        rootNode,
        rootFormat,
        graphSha256,
        orderedNodes,
        orderedOccurrences,
        orderedEdges,
    });
    const traversal = inventoryCoverage(rootFormat, reader, input.traversal);
    const coverage = edgeResult.limitations.length === 0
        ? traversal.coverage
        : { ...traversal.coverage, status: "unknown" };
    return {
        manifest,
        nodes: orderedNodes,
        occurrences: orderedOccurrences,
        edges: orderedEdges,
        provenance: reader?.provenance() ?? [],
        integrity_contradictions: integrityContradictions,
        coverage,
        limitations: buildLimitations([...traversal.limitations, ...edgeResult.limitations], integrityContradictions, input.caseCollisionLimitation),
    };
};
const buildIntegrityContradictions = (pending, occurrenceById, rootNode) => pending.map((contradiction) => {
    const occurrence = contradiction.occurrence;
    const parent = occurrence.parent_occurrence_id === null
        ? undefined
        : occurrenceById.get(occurrence.parent_occurrence_id);
    const parentArtifactId = parent?.artifact_id ?? rootNode.artifact_id;
    return {
        contradiction_id: artifactContradictionId({
            rootArtifactId: rootNode.artifact_id,
            logicalPath: occurrence.logical_path,
            integrity: contradiction.integrity,
        }),
        occurrence_id: occurrence.occurrence_id,
        parent_artifact_id: parentArtifactId,
        logical_path: occurrence.logical_path,
        ...contradiction.integrity,
        entry_kind: contradiction.entryKind,
        unpacked: contradiction.unpacked,
        trust: "observed-untrusted",
        provenance: "container-integrity-metadata-versus-observed-bytes",
        limitations: [
            "Observed bytes contradict declared integrity metadata and cannot support equivalence.",
        ],
    };
});
const verifyRootDigest = async (path, rootDigest, rootSource, resourceScope, signal) => {
    if (rootDigest === null)
        return;
    const verified = rootSource === undefined
        ? await hashStableRootArtifact(path, resourceScope, signal)
        : await hashStableRootArtifactHandle(path, rootSource.handle, rootSource.initial, signal);
    if (verified.sha256 !== rootDigest.sha256 ||
        verified.bytes !== rootDigest.bytes)
        throw new ArtifactReaderFailure("integrity", "Root artifact changed during inventory");
};
const sortNodes = (nodes) => nodes.sort((left, right) => compareUnicodeCodePoints(left.artifact_id, right.artifact_id));
const sortOccurrences = (occurrences) => occurrences.sort((left, right) => compareUnicodeCodePoints(left.logical_path, right.logical_path));
const sortEdges = (edges) => edges.sort((left, right) => compareUnicodeCodePoints(left.edge_id, right.edge_id));
const buildManifest = ({ rootNode, rootFormat, graphSha256, orderedNodes, orderedOccurrences, orderedEdges, }) => artifactInventoryResultSchema.shape.manifest.parse({
    manifest_id: artifactManifestId(rootNode.artifact_id, graphSha256),
    root_artifact_id: rootNode.artifact_id,
    root_sha256: rootNode.sha256,
    root_format: rootFormat,
    graph_sha256: graphSha256,
    node_count: orderedNodes.length,
    occurrence_count: orderedOccurrences.length,
    edge_count: orderedEdges.length,
});
const buildLimitations = (scopeLimitations, integrityContradictions, caseCollisionLimitation) => [
    ...scopeLimitations,
    ...(caseCollisionLimitation === undefined ? [] : [caseCollisionLimitation]),
    ...(integrityContradictions.length === 0
        ? []
        : [
            `${String(integrityContradictions.length)} integrity contradiction(s) were recorded; mismatched content is observed-untrusted.`,
        ]),
];
