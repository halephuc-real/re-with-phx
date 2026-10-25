import { digestCanonicalValue } from "./canonicalDigest.js";
import { compareUnicodeCodePoints, compositeKey, } from "./unicodeCodePointOrder.js";
import { webCaptureDiffSchema, } from "./webCaptureDiffSchemas.js";
import { fingerprintWebCaptureFrames } from "./webCaptureFrameComparison.js";
/** Compare normalized observations without treating incomplete absence as proof. */
export const compareWebCaptures = (input) => {
    const before = input.before.inspection;
    const after = input.after.inspection;
    const dimensions = compareWebCaptureDimensions(input);
    const statuses = Object.values(dimensions).map(({ status }) => status);
    return webCaptureDiffSchema.parse({
        overall_status: statuses.includes("changed")
            ? "changed"
            : statuses.includes("unknown")
                ? "unknown"
                : "unchanged",
        before_target: {
            target_id: before.target.target_id,
            url: before.target.url,
        },
        after_target: {
            target_id: after.target.target_id,
            url: after.target.url,
        },
        dimensions,
        limitations: [
            "A changed status proves an observed difference; an unknown status means absence could not be established from capture completeness.",
            "Network comparison covers only activity observed after each CDP attachment. WebSocket connections with the same URL are compared as an unordered collection of ordered frame streams, retaining connection counts; their individual identities are not stable across captures.",
            "Accessibility roles, ignored state, text, and hierarchy are compared only when the accessibility tree was fully captured and text capture was selected and not truncated.",
            "Storage key inventories are compared only when selected and complete; usage and quota are compared only when reported. Redacted content is compared through complete SHA-256 fingerprints.",
        ],
    });
};
const compareIdentities = (before, after) => {
    const changes = [];
    for (const [identity, fingerprint] of before) {
        const next = after.get(identity);
        if (next === undefined)
            changes.push({ identity, change: "removed" });
        else if (next !== fingerprint)
            changes.push({ identity, change: "modified" });
    }
    for (const identity of after.keys())
        if (!before.has(identity))
            changes.push({ identity, change: "added" });
    return changes.sort((left, right) => compareUnicodeCodePoints(left.identity, right.identity) ||
        compareUnicodeCodePoints(left.change, right.change));
};
const compareDimension = (before, after, complete, reason, inventoryComplete = complete) => {
    // Membership evidence can be complete even when selected content is unknown.
    const all = compareIdentities(before, after).filter(({ identity, change }) => change === "modified" ||
        (typeof inventoryComplete === "boolean"
            ? inventoryComplete
            : inventoryComplete(identity)));
    if (all.length > 0)
        return {
            status: "changed",
            total_changes: all.length,
            changes: all,
            reason: null,
        };
    return complete
        ? {
            status: "unchanged",
            total_changes: 0,
            changes: [],
            reason: null,
        }
        : {
            status: "unknown",
            total_changes: 0,
            changes: [],
            reason,
        };
};
const accessibilityDimension = (before, after) => {
    const beforeAccess = accessibilityComparable(before);
    const afterAccess = accessibilityComparable(after);
    const textComparable = beforeAccess.text && afterAccess.text;
    const nodesComparable = beforeAccess.nodes && afterAccess.nodes;
    const reason = "Accessibility tree or text capture was incomplete in at least one observation.";
    if (!nodesComparable)
        return {
            status: "unknown",
            total_changes: 0,
            changes: [],
            reason,
        };
    return compareDimension(singleton("accessibility_tree", digestCanonicalValue(accessibilityProjection(before.accessibility, textComparable))), singleton("accessibility_tree", digestCanonicalValue(accessibilityProjection(after.accessibility, textComparable))), beforeAccess.complete && afterAccess.complete, reason);
};
const storageDimension = (before, after) => {
    const keysComplete = storageKeysComparable(before) && storageKeysComparable(after);
    const usageComplete = before.storage.usage_bytes !== null &&
        after.storage.usage_bytes !== null &&
        before.storage.quota_bytes !== null &&
        after.storage.quota_bytes !== null;
    const comparableFingerprints = storageFingerprintIdentities(before.storage, after.storage);
    return compareDimension(storageMap(before.storage, keysComplete, usageComplete, comparableFingerprints), storageMap(after.storage, keysComplete, usageComplete, comparableFingerprints), storageComparable(before, after, keysComplete, usageComplete), "Storage fingerprints, inventories, usage, or quota were unavailable or truncated in at least one observation.", keysComplete);
};
const compareWebCaptureDimensions = (input) => {
    const before = input.before.inspection;
    const after = input.after.inspection;
    return {
        dom_structure: domDimension(before, after),
        scripts: compareDimension(keyed(before.scripts.items.map(scriptProjection), (item) => item.script_key), keyed(after.scripts.items.map(scriptProjection), (item) => item.script_key), sectionsComplete(before, ["scripts"]) &&
            sectionsComplete(after, ["scripts"]), "Script inventory was incomplete in at least one observation."),
        resources: compareDimension(keyed(before.resources, (item) => item.resource_key), keyed(after.resources, (item) => item.resource_key), sectionsComplete(before, ["resources"]) &&
            sectionsComplete(after, ["resources"]), "Resource inventory was incomplete in at least one observation."),
        network: networkDimension(before, after),
        metadata: compareAggregate("metadata", metadataProjection(before), metadataProjection(after), sectionsComplete(before, ["metadata"]) &&
            sectionsComplete(after, ["metadata"]), "Safe metadata capture was incomplete in at least one observation."),
        webmcp: webMcpDimension(input.before.webmcp, input.after.webmcp),
        accessibility: accessibilityDimension(before, after),
        storage: storageDimension(before, after),
    };
};
const keyed = (values, identity) => new Map(values.map((value) => [identity(value), digestCanonicalValue(value)]));
const bodyShapesSelected = (inspection) => !inspection.completeness.excluded.some(({ section, reason }) => section === "json_body_shapes" && reason === "not_approved") &&
    (inspection.network.requests.length === 0 ||
        inspection.network.requests.some(({ body_shapes }) => body_shapes.status !== "not_approved"));
const webSocketShapesSelected = (inspection) => !inspection.completeness.excluded.some(({ section, reason }) => section === "websocket_shapes" && reason === "not_approved");
const networkIdentity = (request) => `net_${digestCanonicalValue({ method: request.method, url: request.url, resource_type: request.resource_type })}`;
/** An unknown request type can match any observed type at the same method/URL. */
const networkIdentityCoverage = (before, after) => {
    const complete = [before, after].every((inspection) => inspection.network.requests.every(({ resource_type }) => resource_type !== null));
    const ambiguousIdentities = new Set();
    if (complete)
        return { complete, ambiguousIdentities };
    const matchKey = (request) => JSON.stringify([request.method, request.url]);
    const unknownTypes = (inspection) => {
        const groups = new Map();
        for (const request of inspection.network.requests) {
            const key = matchKey(request);
            groups.set(key, groups.get(key) === true || request.resource_type === null);
        }
        return groups;
    };
    const retainPotentialMatches = (inspection, peer) => {
        for (const request of inspection.network.requests) {
            const peerUnknown = peer.get(matchKey(request));
            if (peerUnknown === true ||
                (peerUnknown === false && request.resource_type === null))
                ambiguousIdentities.add(networkIdentity(request));
        }
    };
    retainPotentialMatches(before, unknownTypes(after));
    retainPotentialMatches(after, unknownTypes(before));
    return { complete, ambiguousIdentities };
};
const networkResponseFields = [
    "status",
    "mime_type",
    "encoded_data_length",
];
const redirectMetadataFields = [
    ...networkResponseFields,
    "resource_type",
];
/** Own both comparable fields and completeness instead of deriving it from set sizes. */
const sharedNetworkMetadata = (before, after) => {
    const shared = new Map();
    let complete = true;
    const retainKnownFields = (identity, metadata, required) => {
        const fields = shared.get(identity) ?? new Set(required);
        for (const field of required)
            if (metadata[field] === null) {
                fields.delete(field);
                complete = false;
            }
        shared.set(identity, fields);
    };
    for (const inspection of [before, after])
        for (const request of inspection.network.requests) {
            const identity = networkIdentity(request);
            retainKnownFields(identity, request, networkResponseFields);
            for (const [index, redirect] of (request.redirects ?? []).entries())
                retainKnownFields(redirectNetworkIdentity(identity, index), redirect, redirectMetadataFields);
        }
    return { fields: shared, complete };
};
const redirectNetworkIdentity = (identity, index) => compositeKey([identity, "redirect", index]);
/** Section lists and per-kind dropped counts independently limit absence evidence. */
const networkInventoryComplete = (inspection, sections) => sectionsComplete(inspection, sections) &&
    sections.every((section) => inspection.completeness.dropped_events[section] === 0);
const webSocketEventHasOpcode = (event) => event !== undefined && event.opcode !== null;
const webSocketEventHasPayloadBytes = (event) => webSocketEventHasOpcode(event) && event.payload_bytes !== null;
const webSocketEventHasPayloadShape = (event) => webSocketEventHasOpcode(event) && event.payload_shape !== null;
const webSocketOpcodesKnown = (inspection) => inspection.network.websocket_connections.every((connection) => connection.events.every(webSocketEventHasOpcode));
const networkDimension = (before, after) => {
    const requestsComplete = [before, after].every((inspection) => networkInventoryComplete(inspection, ["network_requests"]));
    const webSocketInventoryComplete = [before, after].every((inspection) => networkInventoryComplete(inspection, [
        "websocket_connections",
        "websocket_frames",
    ]) && webSocketOpcodesKnown(inspection));
    const requestIdentities = networkIdentityCoverage(before, after);
    const metadata = sharedNetworkMetadata(before, after);
    const selected = bodyShapesSelected(before) && bodyShapesSelected(after);
    const webSocketShapes = webSocketShapesSelected(before) && webSocketShapesSelected(after);
    const projection = {
        metadataFields: metadata.fields,
        ambiguousIdentities: requestIdentities.ambiguousIdentities,
        inventoryComplete: requestsComplete,
    };
    const sources = new Map();
    if (selected) {
        const observedSources = (inspection) => {
            const result = new Map();
            for (const request of inspection.network.requests) {
                const identity = networkIdentity(request);
                const previous = result.get(identity);
                result.set(identity, {
                    request: previous?.request !== false && request.body_shapes.request !== null,
                    response: previous?.response !== false &&
                        request.body_shapes.response !== null,
                });
            }
            return result;
        };
        const left = observedSources(before);
        const right = observedSources(after);
        for (const [identity, coverage] of left) {
            const next = right.get(identity);
            sources.set(identity, {
                request: coverage.request && next?.request === true,
                response: coverage.response && next?.response === true,
            });
        }
    }
    const shapesComplete = !selected ||
        [before, after].every((inspection) => sectionsComplete(inspection, ["json_body_shapes"]) &&
            inspection.network.requests.every(({ body_shapes }) => body_shapes.status === "included"));
    const webSocketShapesComplete = !webSocketShapes ||
        [before, after].every((inspection) => sectionsComplete(inspection, ["websocket_shapes"]) &&
            inspection.network.websocket_connections.every((connection) => connection.events.every(webSocketEventHasPayloadShape)));
    const webSocketPayloadBytesComplete = [before, after].every((inspection) => inspection.network.websocket_connections.every((connection) => connection.events.every(webSocketEventHasPayloadBytes)));
    const beforeWebSockets = webSocketGroups(before);
    const afterWebSockets = webSocketGroups(after);
    const [beforeWebSocketPayload, afterWebSocketPayload] = webSocketPayloadMaps(beforeWebSockets, afterWebSockets, webSocketShapes);
    const compared = compareDimension(new Map([
        ...networkMap(before, sources, projection),
        ...(webSocketInventoryComplete
            ? webSocketMetadataMap(beforeWebSockets)
            : []),
        ...beforeWebSocketPayload,
    ]), new Map([
        ...networkMap(after, sources, projection),
        ...(webSocketInventoryComplete
            ? webSocketMetadataMap(afterWebSockets)
            : []),
        ...afterWebSocketPayload,
    ]), requestsComplete &&
        requestIdentities.complete &&
        webSocketInventoryComplete &&
        shapesComplete &&
        webSocketPayloadBytesComplete &&
        webSocketShapesComplete, requestIdentities.complete
        ? "Network capture or selected HTTP/WebSocket payload-shape coverage is limited, unavailable, incomplete, or includes dropped network events."
        : "HTTP request identity is incomplete because a resource type is unavailable; potentially matching type groups cannot establish membership/content changes or complete network equality.", 
    // HTTP and WebSocket identities have independent inventory coverage. Shape
    // selection can prevent equality without erasing proven membership changes.
    (identity) => identity.startsWith("net_")
        ? requestsComplete
        : identity.startsWith("ws_") && webSocketInventoryComplete);
    if (metadata.complete)
        return compared;
    const responseEvidenceReason = "HTTP response or redirect status, MIME type, byte count, or resource-type evidence is incomplete.";
    if (compared.status === "changed")
        return compared;
    return {
        status: "unknown",
        total_changes: 0,
        changes: [],
        reason: compared.reason === null
            ? responseEvidenceReason
            : `${responseEvidenceReason} ${compared.reason}`,
    };
};
const networkMap = (inspection, sources, projection) => {
    const grouped = new Map();
    for (const request of inspection.network.requests) {
        const identity = networkIdentity(request);
        // A missing type can move repeated requests between these buckets. Neither
        // their counts nor fingerprints establish a change to that typed group.
        if (projection.ambiguousIdentities.has(identity))
            continue;
        const shapes = sources.get(identity);
        const values = grouped.get(identity) ?? [];
        const response = {};
        for (const field of projection.metadataFields.get(identity) ?? [])
            response[field] = request[field];
        values.push(digestCanonicalValue({
            ...response,
            redirects: (request.redirects ?? []).map(({ request_timestamp: _requestTimestamp, redirect_event_timestamp: _redirectEventTimestamp, ...redirect }, index) => {
                const response = {};
                for (const field of projection.metadataFields.get(redirectNetworkIdentity(identity, index)) ?? [])
                    if (redirect[field] !== null)
                        response[field] = redirect[field];
                return {
                    url: redirect.url,
                    response_url: redirect.response_url,
                    method: redirect.method,
                    ...response,
                };
            }),
            initiator: request.initiator,
            ...(shapes?.request === true
                ? { request_shape: request.body_shapes.request }
                : {}),
            ...(shapes?.response === true
                ? { response_shape: request.body_shapes.response }
                : {}),
        }));
        grouped.set(identity, values);
    }
    return new Map([...grouped].map(([identity, values]) => [
        identity,
        digestCanonicalValue(
        // Repeated samples do not establish multiplicity across omissions;
        // keep their known content without interpreting missing rows as change.
        (projection.inventoryComplete ? values : [...new Set(values)]).sort()),
    ]));
};
const webSocketGroups = (inspection) => {
    const groups = new Map();
    for (const connection of inspection.network.websocket_connections) {
        const stream = digestCanonicalValue(connection.events.map(({ direction, opcode }) => ({
            direction,
            opcode,
        })));
        const key = digestCanonicalValue({ url: connection.url, stream });
        const previous = groups.get(key);
        if (previous !== undefined)
            previous.connections.push(connection);
        else
            groups.set(key, {
                url: connection.url,
                stream,
                connections: [connection],
            });
    }
    return groups;
};
const webSocketMetadataMap = (groups) => {
    const byUrl = new Map();
    for (const group of groups.values()) {
        const streams = byUrl.get(group.url) ?? [];
        for (let index = 0; index < group.connections.length; index += 1)
            streams.push(group.stream);
        byUrl.set(group.url, streams);
    }
    return new Map([...byUrl].map(([url, streams]) => [
        `ws_${digestCanonicalValue(url)}`,
        digestCanonicalValue(streams.sort(compareUnicodeCodePoints)),
    ]));
};
const webSocketPayloadMaps = (beforeGroups, afterGroups, selected) => {
    const left = new Map();
    const right = new Map();
    for (const [groupKey, beforeGroup] of beforeGroups) {
        const afterGroup = afterGroups.get(groupKey);
        if (afterGroup === undefined ||
            beforeGroup.connections.length !== afterGroup.connections.length)
            continue;
        const eventCount = beforeGroup.connections[0]?.events.length ?? 0;
        const comparableBytes = new Set();
        const comparableShapes = new Set();
        for (let index = 0; index < eventCount; index += 1) {
            if (beforeGroup.connections.every((connection) => webSocketEventHasPayloadBytes(connection.events[index])) &&
                afterGroup.connections.every((connection) => webSocketEventHasPayloadBytes(connection.events[index])))
                comparableBytes.add(index);
            // Compare only when every same-metadata connection has shape evidence
            // on both sides; this avoids assigning an unknown shape to a known one.
            if (selected &&
                beforeGroup.connections.every((connection) => webSocketEventHasPayloadShape(connection.events[index])) &&
                afterGroup.connections.every((connection) => webSocketEventHasPayloadShape(connection.events[index])))
                comparableShapes.add(index);
        }
        if (comparableBytes.size === 0 && comparableShapes.size === 0)
            continue;
        const project = (group) => digestCanonicalValue(group.connections
            .map((connection) => connection.events.map((event, index) => {
            const comparablePayload = {};
            if (comparableBytes.has(index))
                comparablePayload.payload_bytes = event.payload_bytes;
            if (comparableShapes.has(index))
                comparablePayload.payload_shape = event.payload_shape;
            return Object.keys(comparablePayload).length === 0
                ? null
                : comparablePayload;
        }))
            .map((stream) => digestCanonicalValue(stream))
            .sort(compareUnicodeCodePoints));
        const identity = `wss_${groupKey}`;
        left.set(identity, project(beforeGroup));
        right.set(identity, project(afterGroup));
    }
    return [left, right];
};
const webMcpDimension = (before, after) => {
    const afterTools = new Map(after?.tools.items.map((tool) => [tool.tool_key, tool]));
    const unknownHints = new Set((before?.tools.items ?? [])
        .filter((tool) => {
        const other = afterTools.get(tool.tool_key);
        return (other !== undefined &&
            (tool.annotations.consequential === undefined ||
                other.annotations.consequential === undefined));
    })
        .map((tool) => tool.tool_key));
    const project = (discovery) => keyed((discovery?.tools.items ?? []).map((tool) => {
        if (!unknownHints.has(tool.tool_key))
            return tool;
        const { consequential: _unknown, ...annotations } = tool.annotations;
        return { ...tool, annotations };
    }), (tool) => tool.tool_key);
    const result = compareDimension(project(before), project(after), webMcpComplete(before) && webMcpComplete(after), "WebMCP discovery was unavailable or incomplete in at least one capture.");
    return result.status === "unchanged" && unknownHints.size > 0
        ? {
            ...result,
            status: "unknown",
            reason: "Consequential annotations were not recorded or were invalid in at least one capture.",
        }
        : result;
};
const webMcpComplete = (discovery) => discovery !== null &&
    discovery.status === "available" &&
    !incompleteSections(discovery.completeness).has("webmcp_tools");
const sectionsComplete = (inspection, sections) => {
    const incomplete = incompleteSections(inspection.completeness);
    return sections.every((section) => !incomplete.has(section));
};
const incompleteSections = (completeness) => new Set([
    ...completeness.policy_filtered_sections,
    ...completeness.attach_limited_sections,
    ...completeness.truncated_sections,
    ...completeness.unavailable_sections,
]);
/** Whole-collection digest differences cannot prove a change across omissions. */
const compareAggregate = (identity, before, after, complete, reason) => compareDimension(complete ? singleton(identity, digestCanonicalValue(before)) : new Map(), complete ? singleton(identity, digestCanonicalValue(after)) : new Map(), complete, reason);
const domDimension = (before, after) => {
    const beforeFrames = fingerprintWebCaptureFrames(before.frames);
    const afterFrames = fingerprintWebCaptureFrames(after.frames);
    const nodesComplete = [before, after].every((inspection) => sectionsComplete(inspection, ["dom"]) &&
        inspection.dom.total_nodes === inspection.dom.nodes.length);
    const framesComplete = beforeFrames !== null &&
        afterFrames !== null &&
        [before, after].every((inspection) => sectionsComplete(inspection, ["frames"]));
    const changes = [];
    if (nodesComplete &&
        digestCanonicalValue(before.dom.nodes) !==
            digestCanonicalValue(after.dom.nodes))
        changes.push({ identity: "document", change: "modified" });
    if (framesComplete && beforeFrames !== afterFrames)
        changes.push({ identity: "frames", change: "modified" });
    if (changes.length > 0)
        return {
            status: "changed",
            total_changes: changes.length,
            changes,
            reason: null,
        };
    return nodesComplete && framesComplete
        ? { status: "unchanged", total_changes: 0, changes: [], reason: null }
        : {
            status: "unknown",
            total_changes: 0,
            changes: [],
            reason: "DOM or frame capture was incomplete, or frame ancestry was unresolved in at least one observation.",
        };
};
const scriptProjection = (script) => ({
    script_key: script.script_key,
    url: script.url,
    cdp_hash: script.cdp_hash,
    length: script.length,
    is_module: script.is_module,
    language: script.language,
    source_map_url: script.source_map_url,
});
const metadataProjection = (inspection) => ({
    responses: inspection.metadata.responses
        .map(({ request_id: _requestId, ...response }) => response)
        .map((value) => digestCanonicalValue(value))
        .sort(),
    dom_urls: inspection.metadata.dom_urls
        .map((value) => digestCanonicalValue(value))
        .sort(),
    agent_hints: inspection.metadata.agent_hints
        .map((value) => digestCanonicalValue(value))
        .sort(),
    excluded_dom_urls: inspection.metadata.excluded_dom_urls,
    headers_allowlisted: inspection.metadata.headers_allowlisted,
});
const singleton = (key, value) => new Map([[key, value]]);
const accessibilityComparable = (inspection) => {
    const text = inspection.accessibility.text_capture.status === "included" &&
        inspection.accessibility.text_capture.excluded_fields === 0;
    const { completeness } = inspection;
    const exclusions = completeness.excluded.filter(({ section }) => section === "accessibility");
    const textOnlyPolicyFilter = inspection.accessibility.text_capture.status === "not_approved" &&
        exclusions.length > 0 &&
        exclusions.every(({ reason }) => reason === "not_approved");
    const nodes = [
        completeness.truncated_sections,
        completeness.unavailable_sections,
        completeness.attach_limited_sections,
    ].every((sections) => !sections.includes("accessibility")) &&
        (!completeness.policy_filtered_sections.includes("accessibility") ||
            textOnlyPolicyFilter) &&
        inspection.accessibility.total_nodes ===
            inspection.accessibility.nodes.length;
    const complete = text && nodes;
    return { text, nodes, complete };
};
const accessibilityProjection = (accessibility, includeText) => {
    const nodeIndexes = new Map(accessibility.nodes.map((node, index) => [node.node_id, index]));
    return {
        total_nodes: accessibility.total_nodes,
        nodes: accessibility.nodes.map((node) => ({
            parent_index: node.parent_id === null
                ? null
                : (nodeIndexes.get(node.parent_id) ?? -1),
            role: node.role,
            ignored: node.ignored,
            states: node.states,
            ...(includeText
                ? { name: node.name, description: node.description }
                : {}),
        })),
    };
};
const storageKeysComparable = (inspection) => sectionsComplete(inspection, ["storage_keys"]);
const storageComparable = (before, after, keysComplete, usageComplete) => keysComplete &&
    usageComplete &&
    before.storage.fingerprints_complete &&
    after.storage.fingerprints_complete;
const storageMap = (storage, includeKeys, includeUsage, fingerprintIdentities) => {
    const map = new Map([
        [
            "storage:summary",
            digestCanonicalValue({
                origin: storage.origin,
                values_redacted: storage.values_redacted,
                ...(includeUsage
                    ? {
                        usage_bytes: storage.usage_bytes,
                        quota_bytes: storage.quota_bytes,
                    }
                    : {}),
            }),
        ],
    ]);
    const add = (kind, keys) => {
        for (const key of keys) {
            map.set(`storage:${kind}:${key}`, digestCanonicalValue(key));
        }
    };
    if (includeKeys) {
        add("local_storage", storage.local_storage_keys);
        add("session_storage", storage.session_storage_keys);
        add("indexed_db", storage.indexed_db_names);
        add("cache", storage.cache_names);
    }
    for (const fingerprint of storage.content_fingerprints) {
        const identity = `${fingerprint.scope}:${fingerprint.identity_sha256}`;
        if (!fingerprintIdentities.has(identity))
            continue;
        map.set(`storage:content:${identity}`, digestCanonicalValue(fingerprint.value_sha256));
    }
    return map;
};
const storageFingerprintIdentities = (before, after) => {
    const beforeComplete = completeStorageFingerprints(before);
    const afterComplete = completeStorageFingerprints(after);
    if (before.fingerprints_complete && after.fingerprints_complete)
        return new Set([...beforeComplete.keys(), ...afterComplete.keys()]);
    return new Set([...beforeComplete.keys()].filter((identity) => afterComplete.has(identity)));
};
const completeStorageFingerprints = (storage) => new Map(storage.content_fingerprints
    .filter(({ complete }) => complete)
    .map(({ scope, identity_sha256, value_sha256 }) => [
    `${scope}:${identity_sha256}`,
    value_sha256,
]));
