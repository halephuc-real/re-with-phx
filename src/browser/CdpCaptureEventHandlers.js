import { sanitizeBrowserUrl } from "../domain/browserObservation.js";
import { inferJsonShape } from "../domain/jsonShape.js";
import { paddedBase64ByteLength } from "../domain/paddedBase64.js";
import { safeResponseMetadata } from "./CdpSafeMetadata.js";
import { allowedSanitizedUrl, isHttpUrl, numberValue, recordValue, recordsValue, scriptMetadataValues, cdpStringValue, } from "./CdpCaptureValues.js";
import { requestBodyShape, updateResponseBodyShape, } from "./CdpCaptureEventBodyShapes.js";
import { consolePrimitive, exclusionReasonForUrl, executionContextKey, firstCallFrame, initiatorLocation, integerOrNull, isJsonMediaType, cdpFrameIdentity, } from "./CdpCaptureEventHelpers.js";
import { CDP_CAPTURE_SCRIPT_METADATA_LIMITS, } from "./CdpCaptureEventTypes.js";
export const handleExecutionContextCreated = (state, params) => {
    const context = recordValue(params.context);
    const identifier = numberValue(context?.id);
    const frameId = cdpStringValue(recordValue(context?.auxData)?.frameId);
    if (identifier === undefined ||
        !Number.isSafeInteger(identifier) ||
        frameId === undefined)
        return;
    const key = String(identifier);
    // New contexts may reuse an id. Scripts already parsed keep the frame stored on them.
    state.executionContextFrames.set(key, frameId);
};
export const handleExecutionContextDestroyed = (state, params) => {
    const key = executionContextKey(params.executionContextId);
    if (key !== null)
        state.executionContextFrames.delete(key);
};
export const handleScriptParsed = (state, params) => {
    const scriptId = cdpStringValue(params.scriptId);
    const rawUrl = cdpStringValue(params.url) ?? "";
    const sanitized = allowedSanitizedUrl(rawUrl, state.allowedOrigins);
    if (scriptId === undefined) {
        state.completeness.exclude("scripts", "invalid_protocol_value");
        return;
    }
    const replacedBytes = state.scriptMetadataBytesById.get(scriptId) ?? 0;
    state.scriptMetadataBudgetOmissionsById.delete(scriptId);
    if (replacedBytes > 0) {
        state.scripts.delete(scriptId);
        state.scriptMetadataBytesById.delete(scriptId);
        state.retainedScriptMetadataBytes -= replacedBytes;
    }
    if (sanitized === undefined) {
        state.completeness.exclude("scripts", exclusionReasonForUrl(rawUrl));
        return;
    }
    const executionContext = executionContextKey(params.executionContextId);
    const baseScript = {
        scriptId,
        rawUrl,
        url: sanitized.url,
        origin: sanitized.origin,
        ...scriptMetadataValues(params),
        language: cdpStringValue(params.scriptLanguage) ?? null,
        executionContextKey: executionContext,
        frameId: executionContext === null
            ? null
            : (state.executionContextFrames.get(executionContext) ?? null),
    };
    const baseBytes = scriptMetadataStringBytes(baseScript);
    const sourceMapDeclared = typeof params.sourceMapURL === "string" && params.sourceMapURL.length > 0;
    if (state.scripts.size >= CDP_CAPTURE_SCRIPT_METADATA_LIMITS.scripts ||
        baseBytes >
            CDP_CAPTURE_SCRIPT_METADATA_LIMITS.retainedBytes -
                state.retainedScriptMetadataBytes) {
        state.rejectedScriptMetadataBudgetCount += 1;
        if (sourceMapDeclared)
            state.rejectedSourceMapMetadataBudgetCount += 1;
        return;
    }
    const sourceMap = sourceMapForScript(params.sourceMapURL, rawUrl, state, CDP_CAPTURE_SCRIPT_METADATA_LIMITS.retainedBytes -
        state.retainedScriptMetadataBytes -
        baseBytes);
    const { budgetExhausted, ...sourceMapFields } = sourceMap;
    const script = { ...baseScript, ...sourceMapFields };
    if (budgetExhausted)
        state.scriptMetadataBudgetOmissionsById.set(scriptId, true);
    const retainedBytes = baseBytes +
        stringByteLength(sourceMap.sourceMapUrl) +
        stringByteLength(sourceMap.sourceMapRawUrl);
    state.retainedScriptMetadataBytes += retainedBytes;
    state.scriptMetadataBytesById.set(scriptId, retainedBytes);
    state.scripts.set(scriptId, script);
};
const scriptMetadataStringBytes = (script) => stringByteLength(script.scriptId) +
    stringByteLength(script.rawUrl) +
    stringByteLength(script.url) +
    stringByteLength(script.origin) +
    stringByteLength(script.hash) +
    stringByteLength(script.language) +
    stringByteLength(script.executionContextKey) +
    stringByteLength(script.frameId);
const stringByteLength = (value) => value === null ? 0 : Buffer.byteLength(value, "utf8");
const sourceMapForScript = (value, scriptUrl, state, remainingBytes) => {
    const declaredUrl = cdpStringValue(value);
    if (declaredUrl === undefined || declaredUrl === "")
        return {
            sourceMapUrl: null,
            sourceMapRawUrl: null,
            budgetExhausted: false,
        };
    let rawUrl;
    try {
        rawUrl = new URL(declaredUrl, scriptUrl).href;
    }
    catch (cause) {
        // Unparseable URLs are recorded as unsupported, not as failures.
        void cause;
        state.completeness.exclude("source_maps", "unsupported_url");
        return {
            sourceMapUrl: null,
            sourceMapRawUrl: null,
            budgetExhausted: false,
        };
    }
    const sanitized = allowedSanitizedUrl(rawUrl, state.allowedOrigins);
    if (sanitized !== undefined) {
        if (stringByteLength(rawUrl) + stringByteLength(sanitized.url) >
            remainingBytes) {
            return {
                sourceMapUrl: null,
                sourceMapRawUrl: null,
                budgetExhausted: true,
            };
        }
        return {
            sourceMapUrl: sanitized.url,
            sourceMapRawUrl: rawUrl,
            budgetExhausted: false,
        };
    }
    state.completeness.exclude("source_maps", exclusionReasonForUrl(rawUrl));
    return {
        sourceMapUrl: null,
        sourceMapRawUrl: null,
        budgetExhausted: false,
    };
};
export const handleRequestWillBeSent = (state, params) => {
    const requestId = cdpStringValue(params.requestId);
    const request = recordValue(params.request);
    if (requestId === undefined) {
        state.completeness.exclude("network_requests", "invalid_protocol_value");
        return;
    }
    if (state.malformedRedirectRequestIds.has(requestId))
        return;
    const previous = state.network.get(requestId);
    if (!Object.hasOwn(params, "redirectResponse") &&
        previous !== undefined &&
        preserveMalformedRedirectEvidence(state, requestId, previous))
        return;
    const method = cdpStringValue(request?.method);
    const initiator = recordValue(params.initiator);
    const initiatorType = cdpStringValue(initiator?.type);
    if (request === undefined ||
        method === undefined ||
        method.length === 0 ||
        initiatorType === undefined ||
        initiatorType.length === 0) {
        preserveMalformedRedirectEvidence(state, requestId, previous);
        return;
    }
    const sanitized = allowedSanitizedUrl(request.url, state.allowedOrigins);
    if (sanitized === undefined) {
        state.completeness.exclude("network_requests", exclusionReasonForUrl(cdpStringValue(request.url)));
        state.network.delete(requestId);
        state.networkRequestTimestamps.delete(requestId);
        return;
    }
    const redirectResponse = recordValue(params.redirectResponse);
    if (Object.hasOwn(params, "redirectResponse") &&
        redirectResponse === undefined &&
        preserveMalformedRedirectEvidence(state, requestId, previous))
        return;
    const redirects = [...(previous?.redirects ?? [])];
    if (redirectResponse !== undefined) {
        const rawResponseUrl = cdpStringValue(redirectResponse.url);
        const responseUrl = rawResponseUrl === undefined || rawResponseUrl === ""
            ? undefined
            : allowedSanitizedUrl(rawResponseUrl, state.allowedOrigins);
        const responseUrlReason = redirectResponseUrlReason(rawResponseUrl);
        if (previous === undefined) {
            if (responseUrl === undefined)
                state.completeness.exclude("network_requests", responseUrlReason);
            else
                // CDP may deliver the continuation after its predecessor was excluded
                // by origin policy or before capture began. Keep the final request but
                // report missing prior coverage without calling it malformed protocol.
                state.completeness.attachLimited("network_requests");
        }
        else if (responseUrl === undefined) {
            // redirectResponse belongs to the same request ID and can contain an
            // excluded origin. Drop the entire chain before retaining any details.
            state.completeness.exclude("network_requests", responseUrlReason);
            state.network.delete(requestId);
            state.networkRequestTimestamps.delete(requestId);
            return;
        }
        else {
            const encodedDataLength = numberValue(redirectResponse.encodedDataLength);
            if (encodedDataLength === undefined || encodedDataLength < 0)
                state.completeness.exclude("network_requests", "invalid_protocol_value");
            redirects.push({
                url: previous.url,
                response_url: responseUrl.url,
                method: previous.method,
                resource_type: previous.resource_type,
                status: numberValue(redirectResponse.status) ?? null,
                mime_type: cdpStringValue(redirectResponse.mimeType) ?? null,
                encoded_data_length: encodedDataLength === undefined || encodedDataLength < 0
                    ? null
                    : encodedDataLength,
                request_timestamp: state.networkRequestTimestamps.get(requestId) ?? null,
                // CDP reports redirectResponse on the next requestWillBeSent event.
                // This is the event boundary, not a separately observed response time.
                redirect_event_timestamp: numberValue(params.timestamp) ?? null,
            });
        }
    }
    const initiatorFrame = initiatorLocation(initiator);
    const rawInitiatorUrl = cdpStringValue(initiatorFrame?.url);
    const initiatorUrl = allowedSanitizedUrl(rawInitiatorUrl, state.allowedOrigins);
    if (rawInitiatorUrl !== undefined && initiatorUrl === undefined)
        state.completeness.exclude("network_initiators", exclusionReasonForUrl(rawInitiatorUrl));
    state.network.set(requestId, {
        request_id: requestId,
        url: sanitized.url,
        origin: sanitized.origin ?? "",
        method,
        resource_type: cdpStringValue(params.type) ?? null,
        status: null,
        mime_type: null,
        encoded_data_length: null,
        redirects,
        initiator: {
            type: initiatorType,
            url: initiatorUrl?.url ?? null,
            line: integerOrNull(initiatorFrame?.lineNumber),
            column: integerOrNull(initiatorFrame?.columnNumber),
        },
        body_shapes: requestBodyShape(state, request),
    });
    const timestamp = numberValue(params.timestamp);
    if (timestamp === undefined)
        state.networkRequestTimestamps.delete(requestId);
    else
        state.networkRequestTimestamps.set(requestId, timestamp);
};
const preserveMalformedRedirectEvidence = (state, requestId, previous) => {
    state.completeness.exclude("network_requests", "invalid_protocol_value");
    if (previous === undefined)
        return false;
    state.malformedRedirectRequestIds.add(requestId);
    if (state.input.include_json_body_shapes &&
        isJsonMediaType(previous.mime_type) &&
        previous.body_shapes.response === null) {
        updateResponseBodyShape(state, requestId, null);
        state.completeness.exclude("json_body_shapes", "invalid_protocol_value");
    }
    return true;
};
const redirectResponseUrlReason = (value) => {
    if (value === undefined || value === "")
        return "invalid_protocol_value";
    try {
        new URL(value);
    }
    catch {
        return "invalid_protocol_value";
    }
    return exclusionReasonForUrl(value);
};
export const handleResponseReceived = (state, params) => {
    const requestId = cdpStringValue(params.requestId);
    if (requestId === undefined) {
        state.completeness.exclude("network_requests", "invalid_protocol_value");
        return;
    }
    if (state.malformedRedirectRequestIds.has(requestId))
        return;
    const current = state.network.get(requestId);
    const response = recordValue(params.response);
    if (current === undefined)
        return;
    const sanitized = allowedSanitizedUrl(response?.url, state.allowedOrigins);
    if (response === undefined || sanitized === undefined) {
        state.completeness.exclude("network_requests", response === undefined
            ? "invalid_protocol_value"
            : exclusionReasonForUrl(cdpStringValue(response.url)));
        state.network.delete(requestId);
        state.networkRequestTimestamps.delete(requestId);
        return;
    }
    state.network.set(requestId, {
        ...current,
        status: numberValue(response.status) ?? null,
        mime_type: cdpStringValue(response.mimeType) ?? null,
    });
    const metadata = safeResponseMetadata(requestId, sanitized.url, response, state.allowedOrigins);
    state.responseMetadata.push(metadata.response);
    state.agentHints.push(...metadata.agentHints);
};
export const handleLoadingFinished = (state, params) => {
    const requestId = cdpStringValue(params.requestId);
    if (requestId === undefined)
        return;
    if (state.malformedRedirectRequestIds.has(requestId))
        return;
    const current = state.network.get(requestId);
    if (current === undefined)
        return;
    const encodedDataLength = numberValue(params.encodedDataLength);
    if (encodedDataLength === undefined || encodedDataLength < 0) {
        state.completeness.exclude("network_requests", "invalid_protocol_value");
        return;
    }
    state.network.set(requestId, {
        ...current,
        encoded_data_length: encodedDataLength,
    });
};
export const handleConsoleAPICalled = (state, params) => {
    const frame = firstCallFrame(recordValue(params.stackTrace));
    if (frame === undefined) {
        state.completeness.exclude("console_events", "unattributed_origin");
        return;
    }
    const source = allowedSanitizedUrl(frame.url, state.allowedOrigins);
    if (source === undefined) {
        state.completeness.exclude("console_events", exclusionReasonForUrl(cdpStringValue(frame.url)));
        return;
    }
    const arguments_ = recordsValue(params.args);
    const timestamp = numberValue(params.timestamp);
    if (timestamp === undefined)
        state.completeness.exclude("console_events", "invalid_protocol_value");
    state.console.push({
        type: cdpStringValue(params.type) ?? "unknown",
        timestamp: timestamp ?? null,
        argument_types: arguments_.map((argument) => cdpStringValue(argument.type) ?? "unknown"),
        url: source.url,
        line: integerOrNull(frame.lineNumber),
        column: integerOrNull(frame.columnNumber),
        text_capture: captureConsoleText(state, arguments_),
    });
};
const captureConsoleText = (state, arguments_) => {
    if (!state.input.include_console_text)
        return {
            status: "not_approved",
            values: [],
            retained_bytes: 0,
        };
    const values = [];
    let retainedBytes = 0;
    for (const [argumentIndex, argument] of arguments_.entries()) {
        const primitive = consolePrimitive(argument);
        if (primitive === undefined)
            continue;
        const text = primitive.text;
        values.push({
            argument_index: argumentIndex,
            type: primitive.type,
            text,
        });
        retainedBytes += Buffer.byteLength(text);
    }
    return {
        status: "included",
        values,
        retained_bytes: retainedBytes,
    };
};
export const handleWebSocketFrame = (state, params, direction) => {
    const requestId = cdpStringValue(params.requestId);
    if (requestId === undefined)
        return;
    const connection = state.webSocketConnectionsById.get(requestId);
    if (connection === undefined)
        return;
    const response = recordValue(params.response);
    const opcodeValue = numberValue(response?.opcode);
    // RFC 6455 encodes opcodes in four bits; keep reserved values as observed data.
    const opcode = opcodeValue !== undefined &&
        Number.isInteger(opcodeValue) &&
        opcodeValue >= 0 &&
        opcodeValue <= 15
        ? opcodeValue
        : null;
    const payload = cdpStringValue(response?.payloadData);
    const payloadBytes = opcode === null || payload === undefined
        ? null
        : opcode === 1
            ? Buffer.byteLength(payload)
            : (paddedBase64ByteLength(payload) ?? null);
    if (opcode === null || payloadBytes === null)
        state.completeness.exclude("websocket_frames", "invalid_protocol_value");
    connection.events.push({
        direction,
        opcode,
        payload_bytes: payloadBytes,
        payload_shape: captureWebSocketShape(state, payload, opcode),
    });
};
const captureWebSocketShape = (state, payload, opcode) => {
    if (!state.input.include_websocket_shapes)
        return null;
    if (opcode === null)
        return null;
    if (opcode !== 1)
        return { format: "binary", json_shape: null };
    if (payload === undefined)
        return null;
    const shape = inferJsonShape(payload);
    return {
        format: shape === null ? "text" : "json",
        json_shape: shape,
    };
};
export const handleWebSocketCreated = (state, params) => {
    const requestId = cdpStringValue(params.requestId);
    const rawUrl = cdpStringValue(params.url);
    if (requestId === undefined) {
        state.completeness.exclude("websocket_connections", "invalid_protocol_value");
        return;
    }
    if (rawUrl === undefined) {
        state.completeness.exclude("websocket_connections", "invalid_protocol_value");
        return;
    }
    const sourceUrl = sanitizeBrowserUrl(rawUrl).url;
    let parsed;
    try {
        parsed = new URL(sourceUrl);
    }
    catch (cause) {
        // Unparseable URLs are recorded as unsupported, not as failures.
        void cause;
        state.completeness.exclude("websocket_connections", "unsupported_url");
        return;
    }
    if (parsed.protocol === "ws:")
        parsed.protocol = "http:";
    else if (parsed.protocol === "wss:")
        parsed.protocol = "https:";
    else {
        state.completeness.exclude("websocket_connections", "unsupported_url");
        return;
    }
    if (!state.allowedOrigins.has(parsed.origin)) {
        state.completeness.exclude("websocket_connections", "disallowed_origin");
        return;
    }
    if (state.webSocketConnectionsById.has(requestId)) {
        state.completeness.exclude("websocket_connections", "invalid_protocol_value");
        return;
    }
    state.webSocketConnectionsById.set(requestId, {
        request_id: requestId,
        url: sourceUrl,
        events: [],
    });
};
export const handleFrameNavigated = (state, params) => {
    if (state.mainFrameId === undefined)
        return;
    const identity = cdpFrameIdentity({ method: "Page.frameNavigated", params }, state.mainFrameId);
    if (identity.identityIssue !== null || identity.parentIssue !== null) {
        state.completeness.exclude("frames", "invalid_protocol_value");
        if (identity.selection === "unknown" &&
            identity.parentRelation === "child" &&
            identity.identityIssue !== null)
            return;
        state.unknownRootIdentity = true;
        return;
    }
    if (identity.selection === "other" && identity.parentRelation === "child")
        return;
    if (identity.selection === "unknown") {
        state.completeness.exclude("frames", "invalid_protocol_value");
        state.unknownRootIdentity = true;
        return;
    }
    if (identity.selection === "other" && !identity.isRootReplacement) {
        state.completeness.exclude("frames", "invalid_protocol_value");
        state.unknownRootIdentity = true;
        return;
    }
    const frame = recordValue(recordValue(params)?.frame);
    const rawUrl = cdpStringValue(frame?.url);
    const loaderId = cdpStringValue(frame?.loaderId);
    // `frameNavigated` re-fires for a document already reported (same URL and
    // loader). Treating that as a navigation aborted a valid capture with
    // `target_changed`, which is a false claim that the target moved.
    const document = `${String(identity.frameId ?? "")}\0${String(loaderId ?? "")}\0${String(rawUrl ?? "")}`;
    if (state.committedDocument === document)
        return;
    state.committedDocument = document;
    if (identity.isRootReplacement)
        state.mainFrameId = identity.frameId ?? undefined;
    state.navigationDuringCapture = true;
    if (isHttpUrl(rawUrl) &&
        allowedSanitizedUrl(rawUrl, state.allowedOrigins) === undefined)
        state.originViolation = true;
};
