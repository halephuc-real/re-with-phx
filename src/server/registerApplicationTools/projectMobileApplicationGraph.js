import { runAdmittedToolOperation } from "../admittedToolOperation.js";
import { projectAndroidApplicationEvidence } from "../../application/android/AndroidApplicationService.js";
import { projectAppleApplicationEvidence } from "../../application/apple/AppleApplicationService.js";
import { projectHarmonyApplicationEvidence } from "../../application/harmony/HarmonyApplicationService.js";
import { applicationToolContract, } from "../../contracts/applicationToolContracts.js";
import { recordSessionEvidenceSources } from "../sessionEvidence.js";
import { logToolExecution } from "../toolLogging.js";
import { toolRegistrationOptions } from "../toolRegistrationOptions.js";
import { recordResult } from "./helpers.js";
/** Register execution-free mobile application inventory projection tools. */
export const registerProjectMobileApplicationGraphTools = (server, options) => {
    registerProjection({
        server,
        options,
        contract: applicationToolContract("project_android_application_graph"),
        project: projectAndroidApplicationEvidence,
    });
    registerProjection({
        server,
        options,
        contract: applicationToolContract("project_apple_application_graph"),
        project: projectAppleApplicationEvidence,
    });
    registerProjection({
        server,
        options,
        contract: applicationToolContract("project_harmony_application_graph"),
        project: projectHarmonyApplicationEvidence,
    });
};
const registerProjection = (context) => {
    const { server, options, contract, project } = context;
    server.registerTool(contract.name, toolRegistrationOptions(contract), async (input, request) => runAdmittedToolOperation(server, options.withAdmittedAnalysis, contract.name, request.mcpReq.signal, async () => {
        const result = await logToolExecution(options.logger, contract.name, () => Promise.resolve(project(input)));
        if (!result.ok)
            return server.delivery.toCallToolResult(result, contract);
        const recordedSources = recordSessionEvidenceSources(options.recordEvidence, inventoryEvidenceSources(input));
        if (!recordedSources.ok)
            return server.delivery.toCallToolResult(recordedSources, contract);
        return recordResult({ ...options, delivery: server.delivery }, contract, result.value);
    }));
};
const inventoryEvidenceSources = (input) => {
    if (typeof input !== "object" ||
        input === null ||
        !("inventory_evidence" in input) ||
        !Array.isArray(input.inventory_evidence))
        return [];
    return input.inventory_evidence;
};
