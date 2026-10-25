import { toolContract } from "../contracts/toolContracts.js";
import { matchNativeFunctions } from "../application/native/NativeFunctionMatchingService.js";
import { summarizeRetainedAnalysis } from "../application/analysisView/AnalysisViewService.js";
import { withAdmittedAnalysis } from "./analysisAdmission.js";
import { createEvidenceToolHandler } from "./contractToolHandler.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import { recordSessionEvidenceSources } from "./sessionEvidence.js";
import { matchNativeFunctionsInputSchema } from "../contracts/native/functionMatchingContracts.js";
import { analysisInputErrorFromIssues } from "../domain/inputIssueProjection.js";
import { err, ok } from "../domain/result.js";
/** Bind one named contract to the same retained-Evidence workflow used by CLI. */
export const registerNativeFunctionMatchingTool = (server, session, logger) => {
    const contract = toolContract("match_native_functions");
    const evidenceById = (id) => session.evidenceForAnalysis?.(id) ?? session.evidenceById(id);
    const recordEvidence = (evidence) => session.recordEvidence(evidence);
    const handler = createEvidenceToolHandler(server, async (input, options) => {
        const parsed = matchNativeFunctionsInputSchema.safeParse(input);
        if (!parsed.success)
            return err(analysisInputErrorFromIssues(contract.name, parsed.error.issues, input));
        const result = await matchNativeFunctions(parsed.data, options, evidenceById);
        if (!result.ok)
            return result;
        const recorded = recordSessionEvidenceSources(recordEvidence, result.value.sources);
        if (!recorded.ok)
            return recorded;
        return parsed.data.detail === "summary"
            ? summarizeRetainedAnalysis(result.value.evidence, {
                evidenceById,
                recordEvidence,
            })
            : ok(result.value.evidence);
    }, logger, recordEvidence, withAdmittedAnalysis({ kind: "session", session }));
    server.registerTool(contract.name, toolRegistrationOptions(contract), handler(contract));
};
