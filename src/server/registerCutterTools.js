import { toolContract } from "../contracts/toolContracts.js";
import { evidenceSchema } from "../domain/evidence.js";
import { runWithExternalMutationAdmission, } from "./externalMutationAdmission.js";
import { logToolExecution } from "./toolLogging.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
/** Register Cutter discovery and command tools against their named contracts. */
export const registerCutterTools = (server, service, logger, delivery, recordEvidence, session) => {
    const list = toolContract("list_cutter_sessions");
    const command = toolContract("cutter_command");
    server.registerTool(list.name, toolRegistrationOptions(list), async (_input, context) => {
        const result = await logToolExecution(logger, list.name, () => service.listSessions({ signal: context.mcpReq.signal }));
        if (!result.ok)
            return delivery.toCallToolResult(result, list);
        return delivery.toCallToolResult({
            ok: true,
            value: { ...result.value, sessions: [...result.value.sessions] },
        }, list);
    });
    server.registerTool(command.name, toolRegistrationOptions(command), async (input, context) => {
        const result = await runWithExternalMutationAdmission(session, command.name, context.mcpReq.signal, () => logToolExecution(logger, command.name, () => service.execute(input, { signal: context.mcpReq.signal })), (value) => value, () => service.retryCleanup());
        if (!result.ok) {
            const partial = evidenceSchema.safeParse(result.error.partialObservation);
            if (partial.success) {
                const recorded = recordEvidence?.(partial.data);
                if (recorded !== undefined)
                    return delivery.toRecordedPartialErrorToolResult(result.error, partial.data.evidence_id, recorded, command.returnsTargetContent);
            }
            return delivery.toCallToolResult(result, command);
        }
        return delivery.toEvidenceToolResult(result.value, command, recordEvidence?.(result.value));
    });
};
