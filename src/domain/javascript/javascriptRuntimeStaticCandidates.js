import { posix, win32 } from "node:path";
import { logicalPathEscapesRoot, normalizeJoinedLogicalPath, } from "../artifactIdentity.js";
import { uniqueSorted } from "../canonicalOrdering.js";
import { compareUnicodeCodePoints } from "../unicodeCodePointOrder.js";
/** Index statically reconstructed entities that can receive runtime matches. */
export const collectStaticRuntimeCandidates = (layers) => layers
    .flatMap((layer) => candidatesForLayer(layer))
    .sort((left, right) => compareUnicodeCodePoints(left.layer.layerId, right.layer.layerId) ||
    compareUnicodeCodePoints(left.node.node_id, right.node.node_id));
/** Translate one already-authorized runtime location into artifact paths. */
export const mappedRuntimePaths = (layer, entity) => {
    const paths = [];
    const fileStyle = entity.location.kind === "file"
        ? absoluteFilePathStyle(entity.location.value)
        : null;
    if (entity.location.kind === "file" && layer.result.format === "directory") {
        const path = pathBelowRoot(layer.result.input_path, entity.location.value);
        if (path !== null)
            paths.push({
                path,
                fileStyle,
                nativeRelativePath: path,
                artifactPrefix: "",
                basis: "artifact-path",
            });
    }
    for (const mapping of layer.runtimeMappings) {
        const suffix = mapping.kind === "file-root" && entity.location.kind === "file"
            ? pathBelowRoot(mapping.root, entity.location.value)
            : mapping.kind === "url-prefix" && entity.location.kind === "url"
                ? pathBelowUrlPrefix(mapping.prefix, entity.location.value)
                : null;
        if (suffix === null)
            continue;
        const path = safeArtifactPath(mapping.artifact_prefix, suffix);
        if (path === null)
            continue;
        paths.push({
            path,
            fileStyle,
            nativeRelativePath: mapping.kind === "file-root" ? suffix : null,
            artifactPrefix: normalizeArtifactPrefix(mapping.artifact_prefix),
            basis: mapping.kind === "file-root"
                ? "operator-file-mapping"
                : "operator-url-mapping",
        });
    }
    return uniqueMappedPaths(paths);
};
/** Precompute the artifact prefixes exercised by a bounded runtime set. */
export const createStaticRuntimeScope = (layer, entities) => ({
    artifactPrefixes: activeArtifactPrefixes(layer, entities),
    pathsByNodeId: indexStaticPaths(layer.graph),
});
/** Whether one static node falls under a mapping exercised by this runtime set. */
export const staticNodeWithinRuntimeScope = (node, scope) => (scope.pathsByNodeId.get(node.node_id) ?? []).some((path) => scope.artifactPrefixes.some((prefix) => pathWithinPrefix(path, prefix)));
const candidatesForLayer = (layer) => {
    const graph = layer.graph;
    const pathsByNodeId = indexStaticPaths(graph);
    return graph.nodes.flatMap((node) => {
        const category = candidateCategory(node);
        if (category === null)
            return [];
        return [
            {
                layer,
                node,
                category,
                paths: pathsByNodeId.get(node.node_id) ?? [],
                nativeDeclarationPaths: nativeDeclarationPaths(node),
                digests: candidateDigests(node),
            },
        ];
    });
};
const candidateCategory = (node) => {
    if (node.kind === "electron-renderer")
        return "renderer";
    if (node.kind === "javascript-asset" ||
        (node.kind === "javascript-module" && !isStaticSourceModule(node)))
        return "javascript";
    if (node.kind === "worker")
        return "worker";
    if (node.kind === "service-worker")
        return "service-worker";
    return null;
};
const isStaticSourceModule = (node) => node.observations.some(({ properties }) => properties.semantic_role === "source-module");
const indexStaticPaths = (graph) => {
    const nodes = new Map(graph.nodes.map((candidate) => [candidate.node_id, candidate]));
    const relatedBySource = new Map();
    for (const edge of graph.edges) {
        if (edge.relation !== "maps_to")
            continue;
        const target = nodes.get(edge.target_node_id);
        if (target === undefined)
            continue;
        const related = relatedBySource.get(edge.source_node_id);
        if (related === undefined)
            relatedBySource.set(edge.source_node_id, [target]);
        else
            related.push(target);
    }
    return new Map(graph.nodes.map((node) => [
        node.node_id,
        uniqueSorted([
            ...nodePaths(node),
            ...(usesApplicationFileDeclaration(node)
                ? []
                : (relatedBySource.get(node.node_id) ?? []).flatMap(nodePaths)),
        ]),
    ]));
};
const nodePaths = (node) => {
    const paths = [];
    if (node.identity.strategy === "canonical-path")
        paths.push(node.identity.path);
    for (const observation of node.observations) {
        const rawApplicationFile = node.kind === "electron-renderer" &&
            isRawApplicationFileObservation(observation);
        if (typeof observation.properties.path === "string")
            paths.push(observation.properties.path);
        const applicationPath = ownedApplicationPath(observation);
        if (applicationPath !== undefined)
            paths.push(applicationPath);
        if (rawApplicationFile)
            continue;
        if (typeof observation.properties.resolved_path === "string")
            paths.push(observation.properties.resolved_path);
        const declaration = observation.properties.declared_path;
        if (!hasOwnedArtifactPath(node) &&
            typeof declaration === "string" &&
            !declaration.includes("\\"))
            paths.push(declaration);
        if (observation.evidence.location.available &&
            observation.evidence.location.value.kind === "artifact-path")
            paths.push(observation.evidence.location.value.path);
    }
    return paths
        .map(relativeLogicalPath)
        .filter((path) => path !== null && path !== "artifact-root");
};
// Raw filesystem expressions have host syntax only when a captured file location
// establishes that format. Genuinely owned artifact facts take precedence.
const hasOwnedArtifactPath = (node) => node.identity.strategy === "canonical-path" ||
    node.observations.some(({ properties }) => typeof properties.path === "string") ||
    node.observations.some((observation) => ownedApplicationPath(observation) !== undefined ||
        (!isRawApplicationFileObservation(observation) &&
            typeof observation.properties.resolved_path === "string"));
// Ownership of the application base survives missing target bytes. A confined
// candidate is a path identity, not proof that a static file exists.
const ownedApplicationPath = (observation) => {
    const properties = observation.properties;
    if (properties.runtime_path_base !== "application-root")
        return undefined;
    if (properties.resolution_status === "resolved" &&
        typeof properties.resolved_path === "string")
        return properties.resolved_path;
    if (properties.runtime_path_base_proven === true &&
        (properties.resolution_status === "not-found" ||
            properties.resolution_status === "unavailable") &&
        typeof properties.candidate_path === "string")
        return properties.candidate_path;
    return undefined;
};
// Native declaration matching is needed only without an owned logical path.
const isRawApplicationFileObservation = (observation) => observation.properties.runtime_path_base === "application-root"
    ? ownedApplicationPath(observation) === undefined
    : // Compatibility for captures reconstructed before the producer retained its base.
        observation.properties.resolution_context === "filesystem-expression" &&
            typeof observation.properties.mechanism === "string" &&
            observation.properties.mechanism.startsWith("call:") &&
            observation.properties.mechanism.endsWith("loadFile");
const usesApplicationFileDeclaration = (node) => node.kind === "electron-renderer" &&
    !hasOwnedArtifactPath(node) &&
    node.observations.some(isRawApplicationFileObservation);
const nativeDeclarationPaths = (node) => {
    if (hasOwnedArtifactPath(node))
        return { posix: [], windows: [] };
    const declarations = node.observations.flatMap((observation) => {
        const { properties } = observation;
        return properties.resolution_context === "filesystem-expression" &&
            typeof properties.declared_path === "string" &&
            (isRawApplicationFileObservation(observation) ||
                properties.declared_path.includes("\\"))
            ? [
                {
                    path: properties.declared_path,
                    sourcePath: nativeDeclarationSource(observation),
                },
            ]
            : [];
    });
    const normalized = (windows) => {
        const values = declarations.flatMap(({ path, sourcePath }) => {
            if (windows && (win32.isAbsolute(path) || /^[a-z]:/iu.test(path)))
                return [];
            const normalizedPath = relativeLogicalPath(windows ? path.replaceAll("\\", "/") : path);
            return normalizedPath === null
                ? []
                : [{ path: normalizedPath, sourcePath }];
        });
        return [
            ...new Map(values.map((value) => [JSON.stringify(value), value])).values(),
        ].sort((left, right) => compareUnicodeCodePoints(left.path, right.path) ||
            compareUnicodeCodePoints(left.sourcePath ?? "", right.sourcePath ?? ""));
    };
    return { posix: normalized(false), windows: normalized(true) };
};
// A source anchor constrains the selected application namespace; it does not
// supply a module-relative base for the raw filesystem declaration.
const nativeDeclarationSource = (observation) => {
    const location = observation.evidence.location;
    if (!location.available)
        return null;
    const source = location.value.kind === "source-range"
        ? location.value.source
        : location.value.kind === "artifact-path"
            ? location.value.path
            : null;
    return source === null || source === "artifact-root"
        ? null
        : relativeLogicalPath(source);
};
const candidateDigests = (node) => {
    const values = [];
    if (node.kind === "javascript-asset" &&
        node.identity.strategy === "content-digest")
        values.push({
            sha256: node.identity.sha256,
            basis: "content-sha256",
        });
    if (node.kind === "javascript-module")
        for (const observation of node.observations) {
            const digest = observation.properties.source_sha256;
            if (typeof digest === "string" && /^[a-f0-9]{64}$/u.test(digest))
                values.push({ sha256: digest, basis: "module-source-sha256" });
        }
    return [
        ...new Map(values.map((value) => [`${value.basis}:${value.sha256}`, value])).values(),
    ];
};
const pathBelowRoot = (root, value) => {
    const rootStyle = absoluteFilePathStyle(root);
    if (rootStyle === null || rootStyle !== absoluteFilePathStyle(value))
        return null;
    const remainder = rootStyle === "windows"
        ? win32.relative(root, value)
        : posix.relative(root, value);
    const portableRemainder = rootStyle === "windows" ? remainder.replaceAll("\\", "/") : remainder;
    if (remainder === "" ||
        (rootStyle === "windows" && win32.isAbsolute(remainder)) ||
        portableRemainder === ".." ||
        portableRemainder.startsWith("../"))
        return null;
    return relativeLogicalPath(portableRemainder);
};
const absoluteFilePathStyle = (path) => {
    if (/^[a-z]:[\\/]/iu.test(path) ||
        /^(?:\\\\|\/\/)[^\\/]+[\\/][^\\/]+(?:[\\/]|$)/u.test(path))
        return "windows";
    return path.startsWith("/") ? "posix" : null;
};
const pathBelowUrlPrefix = (prefix, value) => {
    let base;
    let candidate;
    try {
        base = new URL(prefix);
        candidate = new URL(value);
    }
    catch (cause) {
        // Invalid input is represented by the null return.
        void cause;
        return null;
    }
    if (base.origin !== candidate.origin ||
        !candidate.pathname.startsWith(base.pathname))
        return null;
    try {
        return relativeLogicalPath(decodeURIComponent(candidate.pathname.slice(base.pathname.length)));
    }
    catch (cause) {
        // Undecodable path segments are represented by the null return.
        void cause;
        return null;
    }
};
const activeArtifactPrefixes = (layer, entities) => {
    const prefixes = new Set();
    if (layer.result.format === "directory" &&
        entities.some(({ location }) => location.kind === "file" &&
            pathBelowRoot(layer.result.input_path, location.value) !== null))
        prefixes.add("");
    for (const mapping of layer.runtimeMappings)
        if (entities.some(({ location }) => mapping.kind === "file-root" && location.kind === "file"
            ? pathBelowRoot(mapping.root, location.value) !== null
            : mapping.kind === "url-prefix" && location.kind === "url"
                ? pathBelowUrlPrefix(mapping.prefix, location.value) !== null
                : false))
            prefixes.add(normalizeArtifactPrefix(mapping.artifact_prefix));
    return [...prefixes].sort(compareUnicodeCodePoints);
};
const normalizeArtifactPrefix = (prefix) => prefix === "" ? "" : normalizeJoinedLogicalPath(prefix);
const pathWithinPrefix = (path, prefix) => prefix === "" || path === prefix || path.startsWith(`${prefix}/`);
const safeArtifactPath = (prefix, suffix) => relativeLogicalPath(prefix === "" ? suffix : posix.join(prefix, suffix));
const relativeLogicalPath = (value) => {
    // These are artifact names or already parsed runtime paths, not declarations.
    const normalized = normalizeJoinedLogicalPath(value);
    return normalized !== "" &&
        normalized !== "." &&
        !logicalPathEscapesRoot(normalized)
        ? normalized
        : null;
};
const uniqueMappedPaths = (values) => [
    ...new Map(values.map((value) => [
        JSON.stringify([
            value.basis,
            value.path,
            value.fileStyle,
            value.nativeRelativePath,
            value.artifactPrefix,
        ]),
        value,
    ])).values(),
].sort((left, right) => compareUnicodeCodePoints(left.path, right.path) ||
    compareUnicodeCodePoints(left.basis, right.basis) ||
    compareUnicodeCodePoints(left.nativeRelativePath ?? "", right.nativeRelativePath ?? "") ||
    compareUnicodeCodePoints(left.artifactPrefix, right.artifactPrefix));
