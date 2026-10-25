import { inspectAnalysisViewWithFiles } from "../application/analysisView/AnalysisViewService.js";
import { toolContract } from "../contracts/toolContracts.js";
import { createEvidenceToolHandler } from "./contractToolHandler.js";
import { toolRegistrationOptions, applicationValidatedInputSchema, } from "./toolRegistrationOptions.js";
/** Bind selected-view projection to its named contract and session Evidence owner. */
export const registerAnalysisViewTool = (server, logger, evidenceById, recordEvidence, withAdmittedAnalysis, artifactResources) => {
    const contract = toolContract("inspect_analysis_view");
    const registration = toolRegistrationOptions(contract);
    const handler = createEvidenceToolHandler(server, (input, options) => inspectAnalysisViewWithFiles(input, evidenceById, {
        ...(options.signal === undefined ? {} : { signal: options.signal }),
        ...(artifactResources === undefined
            ? {}
            : { resources: artifactResources }),
    }), logger, recordEvidence, withAdmittedAnalysis);
    server.registerTool(contract.name, {
        ...registration,
        inputSchema: applicationValidatedInputSchema(registration.inputSchema),
    }, handler(contract));
};
