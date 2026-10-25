import { isNativeInventoryOperation } from "../domain/native/nativeInventory.js";
import { INSPECT_ANALYSIS_VIEW_OPERATION } from "../domain/analysisView/analysisViewErrors.js";
import { STDIO_DEFAULT_MAX_BUFFER_SIZE } from "@modelcontextprotocol/server";
import { inspectAnalysisViewInputSchema } from "../domain/analysisView/analysisView.js";
import { projectAnalysisError, } from "../domain/analysisErrorProjection.js";
import { jsonValueSchema } from "../domain/jsonValue.js";
import { AnalysisResourceConstraintError } from "../domain/analysisErrorCore.js";
import { encodeToolResult, MCP_RESULT_STRING_LIMIT, TARGET_CONTENT_RESULT_META, } from "./toolResultEncoding.js";
/** Create one delivery policy from the already selected, parsed response budget. */
export const createToolResultDelivery = (maximumResponseBytes) => new ToolResultDelivery(maximumResponseBytes ?? STDIO_DEFAULT_MAX_BUFFER_SIZE);
/** Offer a named, schema-validated source page only for retained native analysis. */
const retainedEvidenceContinuation = (evidence) => {
    const view = evidence.operation === "analyze_function"
        ? { kind: "native", facet: "pseudocode", offset: 0 }
        : isNativeInventoryOperation(evidence.operation)
            ? { kind: "native-inventory", offset: 0, limit: 64 }
            : undefined;
    if (view === undefined)
        return {};
    const input = inspectAnalysisViewInputSchema.safeParse({
        source: { kind: "retained-evidence", evidence_id: evidence.evidence_id },
        view,
    });
    if (!input.success)
        return {};
    return {
        continuation: {
            name: INSPECT_ANALYSIS_VIEW_OPERATION,
            arguments: jsonValueSchema.parse(input.data),
        },
    };
};
/** Immutable encoding and recovery policy shared by one MCP server. */
export class ToolResultDelivery {
    resultBudgetBytes;
    constructor(maximumResponseBytes) {
        this.resultBudgetBytes = maximumResponseBytes - 1024;
        Object.freeze(this);
    }
    /** Serialize a plain application result or its actionable error. */
    toCallToolResult(result, contract) {
        return result.ok
            ? this.successResult(contract.kind === "session" ? { result: result.value } : result.value, contract)
            : this.toErrorToolResult(result.error, contract.returnsTargetContent);
    }
    /** Deliver Evidence using the producer's explicit recording acknowledgment. */
    toEvidenceToolResult(evidence, contract, recorded) {
        return recorded !== undefined && !recorded.ok
            ? this.toErrorToolResult(recorded.error, contract.returnsTargetContent)
            : this.successResult(evidence, contract, {
                evidence_id: evidence.evidence_id,
                ...(recorded === undefined
                    ? {}
                    : {
                        evidence_reference: {
                            kind: "retained-evidence",
                            evidence_id: evidence.evidence_id,
                        },
                        ...retainedEvidenceContinuation(evidence),
                    }),
            });
    }
    /**
     * Project an error without allocating oversized repeated MCP text.
     * `targetContent` is the failing tool's `returnsTargetContent`: a failure
     * can carry target-derived text (a message, captured output, or a partial
     * observation), so it is marked exactly like that tool's successful results.
     */
    toErrorToolResult(error, targetContent) {
        return this.projectedErrorResult(projectAnalysisError(error), targetContent);
    }
    /** Deliver the original failure with the producer-acknowledged partial Evidence reference. */
    toRecordedPartialErrorToolResult(error, evidenceId, recorded, targetContent) {
        if (!recorded.ok)
            return this.toErrorToolResult(error, targetContent);
        const projected = projectAnalysisError(error);
        return this.projectedErrorResult({
            ...projected,
            details: {
                ...projected.details,
                partial_observation: {
                    kind: "retained-evidence",
                    evidence_id: evidenceId,
                },
            },
        }, targetContent);
    }
    projectedErrorResult(projected, targetContent) {
        const structuredContent = { error: projected };
        // Errors reach the wire as text only; the structured copy is a private
        // carrier the transport removes after its own budget check.
        const encoded = encodeToolResult(structuredContent, this.resultBudgetBytes, "error-text", targetContent);
        // The transport retains an oversized projected error before replacing it
        // with a recoverable delivery constraint, using this same budget.
        return {
            content: encoded.ok ? [{ type: "text", text: encoded.text }] : [],
            structuredContent,
            isError: true,
            ...(targetContent ? { _meta: TARGET_CONTENT_RESULT_META } : {}),
        };
    }
    successResult(value, contract, recovery = {}) {
        const encoded = encodeToolResult(value, this.resultBudgetBytes, "structured-and-text", contract.returnsTargetContent);
        if (encoded.ok)
            return {
                content: [{ type: "text", text: encoded.text }],
                structuredContent: value,
                ...(contract.returnsTargetContent
                    ? { _meta: TARGET_CONTENT_RESULT_META }
                    : {}),
            };
        const retainedEvidence = recovery.evidence_reference !== undefined;
        const recoveryAdvice = recovery.continuation !== undefined
            ? "Call inspect_analysis_view with the supplied continuation arguments to read retained analysis. Follow coverage.next_offset for subsequent pages; reduce the page limit if needed, or export the complete retained Evidence."
            : retainedEvidence
                ? "Export retained evidence to consume the complete analysis, or use complete CLI JSON output."
                : encoded.constraint === "string-length"
                    ? "Use complete CLI JSON output to consume the analysis."
                    : "Use a larger MCP response budget with a matching client receive buffer, or use complete CLI JSON output to consume the analysis.";
        return this.toErrorToolResult(new AnalysisResourceConstraintError(contract.name, "transport", encoded.constraint === "string-length"
            ? `The operation completed, but its complete MCP response exceeds Node's single-string representation limit. ${recoveryAdvice}`
            : `The operation completed, but its complete MCP response exceeds the stdio response budget. The analysis result was not truncated. ${recoveryAdvice}`, {
            boundary: "mcp-response",
            default_receive_buffer_bytes: STDIO_DEFAULT_MAX_BUFFER_SIZE,
            result_budget_bytes: this.resultBudgetBytes,
            max_string_code_units: MCP_RESULT_STRING_LIMIT,
            response_bytes_at_least: encoded.bytesAtLeast,
            response_code_units_at_least: encoded.codeUnitsAtLeast,
            constraint: encoded.constraint,
            ...recovery,
        }, recovery.continuation === undefined
            ? undefined
            : { remediationAction: recoveryAdvice }), contract.returnsTargetContent);
    }
}
