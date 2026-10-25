import { summarizeRetainedAnalysis } from "../application/analysisView/AnalysisViewService.js";
import { toolContract } from "../contracts/toolContracts.js";
import { logToolExecution } from "./toolLogging.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import { runAdmittedToolOperation } from "./admittedToolOperation.js";
/** Bind offline layout inspection to its named contract and session Evidence owner. */
export const registerBinaryDiagnosticsTools = (server, service, logger, recordEvidence, evidenceById, withAdmittedAnalysis) => {
    const contract = toolContract("inspect_binary_layout");
    server.registerTool(contract.name, toolRegistrationOptions(contract), async ({ detail, ...request }, context) => runAdmittedToolOperation(server, withAdmittedAnalysis, contract.name, context.mcpReq.signal, async () => {
        const result = await logToolExecution(logger, contract.name, async () => {
            const inspected = await service.inspect(request, {
                signal: context.mcpReq.signal,
            });
            return detail === "summary" && inspected.ok
                ? summarizeRetainedAnalysis(inspected.value, {
                    recordEvidence,
                    evidenceById,
                })
                : inspected;
        });
        if (!result.ok)
            return server.delivery.toCallToolResult(result, contract);
        const recorded = recordEvidence?.(result.value);
        return server.delivery.toEvidenceToolResult(result.value, contract, recorded);
    }));
};
