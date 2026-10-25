import { AsyncLocalStorage } from "node:async_hooks";
import { isCallToolResult, isJSONRPCErrorResponse, isJSONRPCRequest, isJSONRPCNotification, isJSONRPCResultResponse, } from "@modelcontextprotocol/server";
import { analysisErrorProjectionSchema } from "../contracts/errorSchemas.js";
import { presentAdvertisedInputSchema, } from "../contracts/compactInputSchema.js";
import { CATALOG_IDENTITY, createCatalogIdentity } from "../catalogIdentity.js";
import { transformAdvertisedInputJsonSchema } from "../contracts/toolSchemaMetadata.js";
import { AnalysisInputError, AnalysisResourceConstraintError, } from "../domain/analysisErrorCore.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { createEvidence } from "../domain/evidence.js";
import { jsonObjectSchema } from "../domain/jsonValue.js";
import { toolReturnsTargetContent } from "../contracts/toolEffects.js";
import { carriesTargetContentMarker, encodeToolResult, measureMcpResultWithinBudget, TARGET_CONTENT_RESULT_META, } from "./toolResultEncoding.js";
import { RequestTrackingMcpServer } from "./RequestTrackingMcpServer.js";
const currentRequestSignal = new AsyncLocalStorage();
/** Signal for the completion request currently being dispatched by the SDK. */
export const currentMcpRequestSignal = () => currentRequestSignal.getStore();
/** A Zod schema whose standard interface exposes a JSON Schema projection. */
const hasAdvertisedInputJsonSchema = (value) => {
    if (typeof value !== "object" || value === null)
        return false;
    const standard = Reflect.get(value, "~standard");
    if (typeof standard !== "object" || standard === null)
        return false;
    const jsonSchema = Reflect.get(standard, "jsonSchema");
    return (typeof jsonSchema === "object" &&
        jsonSchema !== null &&
        Reflect.get(jsonSchema, "input") !== undefined);
};
const isRecord = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
/** Recognize the SDK's argument diagnostic after its wire size is checked. */
const sdkInputValidationDiagnostic = (text, tool) => {
    if (text === undefined || tool === undefined)
        return undefined;
    const prefix = `Input validation error: Invalid arguments for tool ${tool}`;
    if (!text.startsWith(prefix) || text[prefix.length] !== ":")
        return undefined;
    const diagnostic = text.slice(prefix.length + 1).trimStart();
    return diagnostic.length === 0 ? undefined : diagnostic;
};
/** Replace the tool payload after the SDK codec while retaining its envelope. */
const replaceToolResultPayload = (original, replacement) => {
    const { content: _content, structuredContent: _structuredContent, isError: _isError, _meta, ...envelope } = original;
    return {
        ...envelope,
        ...replacement,
        ...(_meta === undefined && replacement._meta === undefined
            ? {}
            : { _meta: { ..._meta, ...replacement._meta } }),
    };
};
/** Remove only client-facing output schemas; SDK registrations stay canonical. */
const omitOutputSchemasFromToolsList = (message, requestId) => {
    if (!isJSONRPCResultResponse(message) ||
        message.id !== requestId ||
        !isRecord(message.result) ||
        !Array.isArray(message.result.tools))
        return message;
    return {
        ...message,
        result: {
            ...message.result,
            tools: message.result.tools.map((tool) => {
                if (!isRecord(tool))
                    return tool;
                const { outputSchema: _outputSchema, ...advertisedTool } = tool;
                return advertisedTool;
            }),
        },
    };
};
/** Release every transport-owned reference for a cancelled/completed request. */
export const forgetPendingMcpRequest = (pendingTools, pendingToolLists, pendingCompletions, id) => {
    pendingTools.delete(id);
    pendingToolLists.delete(id);
    pendingCompletions.get(id)?.abort();
    pendingCompletions.delete(id);
};
/** Bind oversized MCP error recovery to this server's Evidence ledger. */
export class EvidenceMcpServer extends RequestTrackingMcpServer {
    recordEvidence;
    delivery;
    omitOutputSchemas;
    catalogIdentity;
    compactPresentation;
    constructor(info, options, recordEvidence, delivery, compactPresentation = undefined, omitOutputSchemas = false) {
        super(info, options);
        this.recordEvidence = recordEvidence;
        this.delivery = delivery;
        this.omitOutputSchemas = omitOutputSchemas;
        this.compactPresentation =
            compactPresentation === undefined
                ? undefined
                : { budgetBytes: compactPresentation.budgetBytes };
        this.catalogIdentity =
            this.compactPresentation === undefined && !this.omitOutputSchemas
                ? CATALOG_IDENTITY
                : createCatalogIdentity(this.compactPresentation, this.omitOutputSchemas ? "off" : "full");
    }
    /**
     * Compact advertised input schemas and optionally omit output-schema
     * advertisements. Canonical parsers and contracts remain registered; the
     * output-schema-off path validates successful structured results locally.
     * The signatures mirror the SDK's registrations so call sites keep their
     * inferred handler argument types.
     */
    registerTool(name, config, callback) {
        const budget = this.compactPresentation?.budgetBytes;
        const inputSchema = budget !== undefined &&
            config !== undefined &&
            hasAdvertisedInputJsonSchema(config.inputSchema)
            ? transformAdvertisedInputJsonSchema(config.inputSchema, (projected) => presentAdvertisedInputSchema(projected, { budgetBytes: budget }))
            : undefined;
        const registeredConfig = inputSchema === undefined ? config : { ...config, inputSchema };
        return super.registerTool(name, registeredConfig, callback);
    }
    /** Preserve the SDK transport lifecycle while retaining oversized errors. */
    connect(transport) {
        return super.connect(new ErrorEvidenceTransport(transport, this.recordEvidence, this.delivery, this.omitOutputSchemas));
    }
}
class ErrorEvidenceTransport {
    transport;
    recordEvidence;
    delivery;
    omitOutputSchemas;
    onclose;
    onerror;
    onmessage;
    hasPerRequestStream;
    pendingTools = new Map();
    pendingToolLists = new Set();
    pendingCompletions = new Map();
    constructor(transport, recordEvidence, delivery, omitOutputSchemas) {
        this.transport = transport;
        this.recordEvidence = recordEvidence;
        this.delivery = delivery;
        this.omitOutputSchemas = omitOutputSchemas;
        if (transport.hasPerRequestStream !== undefined)
            this.hasPerRequestStream = transport.hasPerRequestStream;
        transport.onmessage = (message, extra) => {
            if (isJSONRPCRequest(message) &&
                message.method === "tools/call" &&
                typeof message.params?.["name"] === "string")
                this.pendingTools.set(message.id, message.params["name"]);
            if (isJSONRPCRequest(message) && message.method === "tools/list")
                this.pendingToolLists.add(message.id);
            if (isJSONRPCRequest(message) && message.method === "completion/complete")
                this.pendingCompletions.set(message.id, new AbortController());
            // The SDK suppresses replies after cancellation, so send() cannot release
            // this bookkeeping. Keep transport authentication outside retained data.
            if (isJSONRPCNotification(message) &&
                message.method === "notifications/cancelled") {
                const id = message.params?.["requestId"];
                if (typeof id === "string" || typeof id === "number")
                    forgetPendingMcpRequest(this.pendingTools, this.pendingToolLists, this.pendingCompletions, id);
            }
            const completion = isJSONRPCRequest(message) && message.method === "completion/complete"
                ? this.pendingCompletions.get(message.id)
                : undefined;
            if (completion === undefined)
                this.onmessage?.(message, extra);
            else
                currentRequestSignal.run(completion.signal, () => this.onmessage?.(message, extra));
        };
        transport.onerror = (error) => this.onerror?.(error);
        transport.onclose = () => {
            this.pendingTools.clear();
            this.pendingToolLists.clear();
            for (const completion of this.pendingCompletions.values())
                completion.abort();
            this.pendingCompletions.clear();
            this.onclose?.();
        };
    }
    get sessionId() {
        return this.transport.sessionId;
    }
    set sessionId(value) {
        this.transport.sessionId = value;
    }
    start() {
        return this.transport.start();
    }
    async close() {
        try {
            await this.transport.close();
        }
        finally {
            this.pendingTools.clear();
            this.pendingToolLists.clear();
            for (const completion of this.pendingCompletions.values())
                completion.abort();
            this.pendingCompletions.clear();
        }
    }
    setProtocolVersion(version) {
        this.transport.setProtocolVersion?.(version);
    }
    setSupportedProtocolVersions(versions) {
        this.transport.setSupportedProtocolVersions?.(versions);
    }
    async send(message, options) {
        const id = "id" in message &&
            (typeof message.id === "string" || typeof message.id === "number")
            ? message.id
            : undefined;
        const tool = id === undefined ? undefined : this.pendingTools.get(id);
        const omitToolSchemas = this.omitOutputSchemas &&
            id !== undefined &&
            this.pendingToolLists.has(id);
        try {
            const recovered = this.recoverProtocolError(message, tool);
            const advertised = omitToolSchemas
                ? omitOutputSchemasFromToolsList(recovered, id)
                : recovered;
            if (isJSONRPCResultResponse(advertised) &&
                isCallToolResult(advertised.result) &&
                advertised.result.isError === true) {
                // Keep the complete typed JSON in content. Error projections are not
                // success outputSchema data; oversized recovery must consume their
                // private structured carrier before it is removed from the wire.
                const { structuredContent: _diagnostic, ...result } = advertised.result;
                // Errors the SDK builds itself (input validation, a thrown handler)
                // bypass ToolResultDelivery; mark them for target-content tools too.
                const marked = tool !== undefined &&
                    toolReturnsTargetContent(tool) &&
                    !carriesTargetContentMarker(result)
                    ? {
                        ...result,
                        _meta: { ...result._meta, ...TARGET_CONTENT_RESULT_META },
                    }
                    : result;
                await this.transport.send({ ...advertised, result: marked }, options);
            }
            else
                await this.transport.send(advertised, options);
        }
        finally {
            if (!isJSONRPCRequest(message) && id !== undefined) {
                forgetPendingMcpRequest(this.pendingTools, this.pendingToolLists, this.pendingCompletions, id);
            }
        }
    }
    recoverError(message, tool) {
        if (!isJSONRPCResultResponse(message) ||
            !isCallToolResult(message.result) ||
            message.result.isError !== true)
            return message;
        const budget = this.delivery.resultBudgetBytes;
        // Count the provenance marker exactly as the projected error did, and keep
        // it on the replacement: the retained original may hold target content.
        const targetContent = carriesTargetContentMarker(message.result) ||
            (tool !== undefined && toolReturnsTargetContent(tool));
        // SDK validation failures have no structured carrier. Size their existing
        // text-only result without serializing the complete JSON-RPC message.
        const isStructured = message.result.structuredContent !== undefined;
        const structured = isStructured
            ? jsonObjectSchema.parse(message.result.structuredContent)
            : undefined;
        const sdkResultWithMarker = !isStructured &&
            targetContent &&
            !carriesTargetContentMarker(message.result)
            ? {
                ...message.result,
                _meta: {
                    ...message.result._meta,
                    ...TARGET_CONTENT_RESULT_META,
                },
            }
            : message.result;
        const sdkDiagnostic = !isStructured
            ? message.result.content.find((item) => item.type === "text")?.text
            : undefined;
        let encoded = structured !== undefined
            ? encodeToolResult(structured, budget, "error-text", targetContent)
            : measureMcpResultWithinBudget(sdkResultWithMarker, budget);
        const normalized = encoded.ok
            ? this.normalizeSdkValidationError(message, tool, targetContent, sdkInputValidationDiagnostic(sdkDiagnostic, tool))
            : undefined;
        if (normalized !== undefined &&
            isJSONRPCResultResponse(normalized) &&
            isCallToolResult(normalized.result)) {
            // The structured diagnostic is a private carrier removed before sending.
            // Measure the actual wire result, including its preserved SDK metadata.
            const { structuredContent, ...wireResult } = normalized.result;
            encoded =
                normalized.result.content.length === 0
                    ? encodeToolResult(jsonObjectSchema.parse(structuredContent), budget, "error-text", targetContent)
                    : measureMcpResultWithinBudget(wireResult, budget);
            if (encoded.ok)
                return normalized;
            // JSON escaping and recovery fields can exceed the budget even when
            // the original SDK result fits. Retain that original before replacing it.
        }
        if (encoded.ok)
            return message;
        const operation = tool ?? "mcp_tool_error";
        const originalResult = jsonObjectSchema.parse(message.result);
        const retainedResult = structured ?? originalResult;
        const originalError = isStructured
            ? analysisErrorProjectionSchema.safeParse(structured?.["error"])
            : undefined;
        // Retain the complete original response, including SDK validation text.
        // The SDK error contains its rendered issue, not a separate argument bag;
        // transport authentication and caller arguments are never added here.
        const evidence = createEvidence(undefined, { id: "phxre-mcp", name: "PhxRE MCP delivery", version: "1" }, {
            operation: "mcp_tool_error",
            parameters: { tool_name: operation },
            result: sdkDiagnostic === undefined
                ? retainedResult
                : {
                    boundary: "sdk-input-validation",
                    diagnostic_preview: sdkDiagnostic.slice(0, 256),
                    diagnostic_truncated: sdkDiagnostic.length > 256,
                },
            rawResult: originalResult,
        });
        const recorded = this.recordEvidence?.(evidence);
        const retained = recorded !== undefined && recorded.ok;
        const failure = new AnalysisResourceConstraintError(operation, "transport", "The tool failed, but its complete error response exceeds the MCP response budget.", {
            boundary: "mcp-response",
            ...(originalError?.success
                ? { original_error_code: originalError.data.code }
                : {}),
            result_budget_bytes: budget,
            response_bytes_at_least: encoded.bytesAtLeast,
            constraint: encoded.constraint,
            ...(sdkDiagnostic === undefined
                ? {}
                : {
                    diagnostic_preview: sdkDiagnostic.slice(0, 256),
                    diagnostic_truncated: sdkDiagnostic.length > 256,
                }),
            ...(retained
                ? {
                    evidence_reference: {
                        kind: "retained-evidence",
                        evidence_id: evidence.evidence_id,
                    },
                }
                : { retention: recorded === undefined ? "unavailable" : "failed" }),
            ...(recorded !== undefined && !recorded.ok
                ? { retention_error: projectAnalysisError(recorded.error) }
                : {}),
        }, {
            remediationAction: retained
                ? "Export the retained original error through export_evidence_bundle to a caller-selected path. The connection remains usable."
                : "Restart PhxRE with a larger PHXRE_MCP_MAX_RESPONSE_BYTES and matching client receive buffer, then retry. The original error could not be retained by this server.",
        });
        const replacement = this.delivery.toErrorToolResult(failure, targetContent);
        return {
            ...message,
            result: replaceToolResultPayload(message.result, replacement),
        };
    }
    normalizeSdkValidationError(message, tool, targetContent, diagnostic) {
        if (tool === undefined ||
            diagnostic === undefined ||
            !isJSONRPCResultResponse(message) ||
            !isCallToolResult(message.result))
            return undefined;
        const error = new AnalysisInputError(tool, {
            userMessage: `The arguments for MCP tool ${tool} do not match its advertised input schema.`,
        }, [{ path: [], reason: "invalid_value", message: diagnostic }]);
        const result = this.delivery.toErrorToolResult(error, targetContent);
        return {
            ...message,
            result: replaceToolResultPayload(message.result, result),
        };
    }
    recoverProtocolError(message, tool) {
        const recovered = this.recoverError(message, tool);
        if (!isJSONRPCErrorResponse(recovered) ||
            tool === undefined ||
            recovered.error.code !== -32602 ||
            recovered.error.message !== `Tool ${tool} not found`)
            return recovered;
        return {
            ...recovered,
            error: {
                ...recovered.error,
                message: "The requested MCP tool is not advertised by this PhxRE server. Call tools/list, select an advertised tool, and retry; do not repeat the unknown tool name.",
            },
        };
    }
}
