import { createEvidence } from "../domain/evidence.js";
import { jsonObjectSchema } from "../domain/jsonValue.js";
import { ok } from "../domain/result.js";
import { mcpProgressReporter } from "./mcpProgress.js";
import { logToolExecution } from "./toolLogging.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
/** Register provider-backed contracts that return atomic Evidence observations. */
export const registerEvidenceTools = (server, contracts, options) => {
    for (const contract of contracts) {
        server.registerTool(contract.name, toolRegistrationOptions(contract), async (input, context) => {
            const ready = options.preflight?.(contract.name, jsonObjectSchema.parse(input));
            if (ready !== undefined && !ready.ok)
                return server.delivery.toCallToolResult(ready, contract);
            const admitted = await options.withAdmittedAnalysis(contract.name, context.mcpReq.signal, async (admittedAnalysis) => {
                const analysis = options.analysisForAdmission?.(admittedAnalysis) ??
                    admittedAnalysis;
                const progress = mcpProgressReporter(context);
                await progress.report({
                    phase: contract.name,
                    completed: 0,
                    total: 1,
                    message: "started",
                });
                const parameters = jsonObjectSchema.parse(input);
                const executionParameters = options.parametersForExecution?.(contract.name, parameters) ??
                    parameters;
                const execution = await logToolExecution(options.logger, contract.name, () => analysis.execute(contract.name, executionParameters, {
                    signal: context.mcpReq.signal,
                    progress,
                }));
                await progress.report({
                    phase: contract.name,
                    completed: 1,
                    total: 1,
                    message: execution.ok ? "completed" : "failed",
                    terminal: true,
                });
                if (!execution.ok)
                    return server.delivery.toCallToolResult(execution, contract);
                const sourceEvidence = options.sourceEvidence?.(contract.name, execution.value.result) ??
                    [];
                const evidence = createEvidence(execution.value.subject === undefined
                    ? options.activeTarget?.()
                    : (execution.value.subject ?? undefined), execution.value.provider, {
                    operation: contract.name,
                    parameters: options.parametersForEvidence?.(contract.name, parameters) ??
                        parameters,
                    result: execution.value.result,
                    ...(execution.value.analysisProfile === undefined
                        ? {}
                        : { analysisProfile: execution.value.analysisProfile }),
                    rawResult: execution.value.rawResult,
                    limitations: execution.value.limitations,
                    ...(execution.value.relationshipCoverage === undefined
                        ? {}
                        : {
                            relationshipCoverage: execution.value.relationshipCoverage,
                        }),
                    locations: execution.value.locations,
                    evidenceLinks: sourceEvidence.map(({ evidence_id: id }) => id),
                });
                for (const source of sourceEvidence) {
                    const sourceRecorded = options.recordEvidence?.(source);
                    if (sourceRecorded !== undefined && !sourceRecorded.ok)
                        return server.delivery.toCallToolResult(sourceRecorded, contract);
                }
                const projected = options.projectEvidence?.(contract.name, parameters, evidence) ??
                    ok(evidence);
                if (!projected.ok)
                    return server.delivery.toCallToolResult(projected, contract);
                const recorded = options.recordEvidence?.(projected.value);
                return server.delivery.toEvidenceToolResult(projected.value, contract, recorded);
            });
            return admitted.ok
                ? admitted.value
                : server.delivery.toCallToolResult(admitted, contract);
        });
    }
};
