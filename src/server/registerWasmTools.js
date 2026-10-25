import { compareWasmInterfaces } from "../application/wasm/WasmInterfaceComparisonService.js";
import { COMPARE_WASM_INTERFACES_CONTRACT } from "../contracts/wasm/wasmComparisonContracts.js";
import { resolvePairedEvidenceRequest } from "../application/EvidenceInputResolver.js";
import { recordSessionEvidenceSources } from "./sessionEvidence.js";
import { summarizeRetainedAnalysis } from "../application/analysisView/AnalysisViewService.js";
import { analysisInputErrorFromIssues } from "../domain/inputIssueProjection.js";
import { err } from "../domain/result.js";
import { wasmArtifactModule } from "../composition/wasm.js";
import { createEvidenceToolHandler } from "./contractToolHandler.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
/** Bind the named WASM contract to shared validation and session Evidence recording. */
export const registerWasmTools = (server, service, logger, recordEvidence, withAdmittedAnalysis, evidenceById) => {
    const comparison = COMPARE_WASM_INTERFACES_CONTRACT;
    const compareHandler = createEvidenceToolHandler(server, async (rawInput, options) => {
        const input = comparison.inputSchema.safeParse(rawInput);
        if (!input.success)
            return err(analysisInputErrorFromIssues(comparison.name, input.error.issues, rawInput));
        const sources = resolvePairedEvidenceRequest(input.data, evidenceById);
        if (!sources.ok)
            return sources;
        const result = await compareWasmInterfaces(sources.value, options);
        if (!result.ok)
            return result;
        const recorded = recordSessionEvidenceSources(recordEvidence, [
            sources.value.left,
            sources.value.right,
        ]);
        return recorded.ok ? result : recorded;
    }, logger, recordEvidence, withAdmittedAnalysis);
    server.registerTool(comparison.name, toolRegistrationOptions(comparison), compareHandler(comparison));
    const contract = wasmArtifactModule.contract;
    const handler = createEvidenceToolHandler(server, async (rawInput, options) => {
        const parsed = contract.inputSchema.safeParse(rawInput);
        if (!parsed.success)
            return err(analysisInputErrorFromIssues(contract.name, parsed.error.issues, rawInput, { cause: parsed.error }));
        const { detail, ...input } = parsed.data;
        const inspected = await service.inspect(input, options);
        return detail === "summary" && inspected.ok
            ? summarizeRetainedAnalysis(inspected.value, {
                recordEvidence,
                evidenceById,
            })
            : inspected;
    }, logger, recordEvidence, withAdmittedAnalysis);
    server.registerTool(contract.name, toolRegistrationOptions(contract), handler(contract));
};
