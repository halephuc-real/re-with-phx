import { createEvidence } from "../../domain/evidence.js";
/** Preserve the same validated inference and provenance on success and failed finalization. */
export const evmInterfaceEvidence = (input, execution) => createEvidence(execution.subject, execution.provider, {
    operation: "inspect_evm_interface",
    parameters: input,
    result: execution.result,
    ...(execution.rawResult === null ? {} : { rawResult: execution.rawResult }),
    confidence: "inferred",
    locations: execution.locations,
    limitations: execution.limitations,
});
