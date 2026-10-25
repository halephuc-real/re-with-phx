import { resolvePairedEvidenceRequest } from "../application/EvidenceInputResolver.js";
import { createEvidence, parseEvidence, } from "../domain/evidence.js";
import { EvidenceIntegrityError } from "../domain/evidenceErrors.js";
import { err } from "../domain/result.js";
import { jsonValueSchema } from "../domain/jsonValue.js";
import { recordDerivedEvidence } from "./recordDerivedEvidence.js";
import { recordSessionEvidenceSources } from "./sessionEvidence.js";
import { runDerivedOperation } from "./runDerivedOperation.js";
import { FUNCTION_COMPARISON_PROVIDER } from "../application/InvestigationProviders.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import { withAdmittedAnalysis } from "./analysisAdmission.js";
import { runAdmittedToolOperation } from "./admittedToolOperation.js";
import { compareFunctions } from "../domain/functionComparison.js";
import { uniqueSorted } from "../domain/canonicalOrdering.js";
/** Register explicit Evidence-backed function comparison. */
export const registerFunctionComparisonTool = (server, session, contract) => {
    const admission = withAdmittedAnalysis({ kind: "session", session });
    server.registerTool(contract.name, toolRegistrationOptions(contract), async (input, context) => runAdmittedToolOperation(server, admission, contract.name, context.mcpReq.signal, async () => {
        const resolved = resolvePairedEvidenceRequest(input, (id) => session.evidenceForAnalysis?.(id) ?? session.evidenceById(id));
        if (!resolved.ok)
            return server.delivery.toCallToolResult(resolved, contract);
        let leftEvidence;
        let rightEvidence;
        try {
            leftEvidence = parseEvidence(resolved.value.left);
            rightEvidence = parseEvidence(resolved.value.right);
        }
        catch (cause) {
            return server.delivery.toCallToolResult(err(new EvidenceIntegrityError(cause instanceof Error ? cause.message : "Invalid Evidence")), contract);
        }
        if (leftEvidence.operation !== "analyze_function" ||
            rightEvidence.operation !== "analyze_function" ||
            leftEvidence.predicate_type !== "phxre.analysis" ||
            rightEvidence.predicate_type !== "phxre.analysis")
            return server.delivery.toCallToolResult(err(new EvidenceIntegrityError("Expected analyze_function Evidence")), contract);
        const leftIds = [leftEvidence.evidence_id];
        const rightIds = [rightEvidence.evidence_id];
        const computed = await runDerivedOperation(context, contract.name, () => compareFunctions(leftEvidence, rightEvidence));
        if (!computed.ok)
            return server.delivery.toCallToolResult(computed, contract);
        const comparison = computed.value;
        const recordedSources = recordSessionEvidenceSources((evidence) => session.recordEvidence(evidence), [leftEvidence, rightEvidence]);
        if (!recordedSources.ok)
            return server.delivery.toCallToolResult(recordedSources, contract);
        const evidence = createEvidence(undefined, FUNCTION_COMPARISON_PROVIDER, {
            predicateType: "phxre.function-comparison",
            operation: contract.name,
            parameters: {
                left_evidence_id: leftEvidence.evidence_id,
                right_evidence_id: rightEvidence.evidence_id,
            },
            result: jsonValueSchema.parse(comparison),
            confidence: "derived",
            authority: "analyst-inference",
            limitations: comparison.limitations,
            evidenceLinks: [...leftIds, ...rightIds],
        });
        const recorded = recordDerivedEvidence(session, evidence, comparisonUnknownInput(comparison, leftIds, rightIds, evidence.evidence_id));
        return server.delivery.toEvidenceToolResult(evidence, contract, recorded);
    }));
};
const comparisonUnknownInput = (comparison, leftIds, rightIds, comparisonEvidenceId) => functionUnknownInput({
    status: comparison.status,
    dimensions: comparison.dimensions
        .filter(({ status }) => comparison.status === "unknown"
        ? status === "unknown"
        : status === "changed")
        .map(({ dimension }) => dimension),
    leftIds,
    rightIds,
    comparisonEvidenceId,
});
const functionUnknownInput = ({ status, dimensions, leftIds, rightIds, comparisonEvidenceId, }) => {
    if (status === "unchanged")
        return undefined;
    const supportingIds = [
        ...new Set([...leftIds, ...rightIds, comparisonEvidenceId]),
    ];
    const contradictingIds = rightIds.filter((id) => !leftIds.includes(id));
    const contradictory = status === "changed";
    return {
        question: `Function comparison is ${status} (comparison ${comparisonEvidenceId})`,
        severity: status === "changed" ? "medium" : "high",
        domain: "function-comparison",
        comparison_conclusion_scope: {
            comparison_evidence_id: comparisonEvidenceId,
            dimensions: uniqueSorted([
                ...(status === "unknown" || dimensions.length === 0
                    ? ["overall"]
                    : []),
                ...dimensions,
            ]),
        },
        supporting_evidence_ids: contradictory
            ? [...leftIds, comparisonEvidenceId]
            : supportingIds,
        contradicting_evidence_ids: contradictory ? contradictingIds : [],
        required_authority: "shipped-artifact",
        required_confidence: "observed",
        required_environment: null,
        recommended_probes: [
            {
                operation: "analyze_function",
                rationale: "Capture complete dossiers for both functions under the same target context.",
            },
        ],
        relationships: [],
    };
};
