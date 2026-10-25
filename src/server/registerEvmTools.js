import { requireAnalysisViewRetention, summarizeRetainedAnalysis, } from "../application/analysisView/AnalysisViewService.js";
import { analysisInputErrorFromIssues } from "../domain/inputIssueProjection.js";
import { err } from "../domain/result.js";
import { evmInterfaceModule } from "../composition/evm.js";
import { createEvidenceToolHandler } from "./contractToolHandler.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
/** Bind the named EVM contract to shared validation and session Evidence recording. */
export const registerEvmTools = (server, service, logger, recordEvidence, withAdmittedAnalysis, evidenceById) => {
    const contract = evmInterfaceModule.contract;
    const handler = createEvidenceToolHandler(server, async (rawInput, options) => {
        const parsed = contract.inputSchema.safeParse(rawInput);
        if (!parsed.success)
            return err(analysisInputErrorFromIssues(contract.name, parsed.error.issues, rawInput, { cause: parsed.error }));
        const { detail, ...input } = parsed.data;
        const retention = { recordEvidence, evidenceById };
        if (detail === "summary") {
            const ready = requireAnalysisViewRetention(contract.name, retention);
            if (!ready.ok)
                return ready;
        }
        const inspected = await service.inspect(input, options);
        return detail === "summary" && inspected.ok
            ? summarizeRetainedAnalysis(inspected.value, retention)
            : inspected;
    }, logger, recordEvidence, withAdmittedAnalysis);
    server.registerTool(contract.name, toolRegistrationOptions(contract), handler(contract));
};
