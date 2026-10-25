import { z } from "incur";
import { parseEvidence } from "../domain/evidence.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { AnalysisInputError } from "../domain/analysisErrorCore.js";
import { createEvidenceBundle } from "../domain/evidenceBundle.js";
import { writeEvidenceBundle } from "../application/EvidenceBundleFiles.js";
import { inspectAnalysisView } from "../application/analysisView/AnalysisViewService.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { absoluteCallerPath } from "../filesystem/callerPath.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";
export const analysisEvidenceDeliveryOptions = {
    detail: z
        .enum(["complete", "summary"])
        .default("complete")
        .describe("Deliver complete Evidence, or a summary with --evidence_output"),
    evidence_output: z
        .string()
        .min(1)
        .optional()
        .describe("Save complete Evidence as a bundle; required for summary delivery. Never overwrites."),
};
const isEvidence = (value) => typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    "evidence_id" in value &&
    "normalized_result" in value;
export const cliEvidenceDeliveryInputError = (input) => input.detail === "summary" && input.evidenceOutput === undefined
    ? new AnalysisInputError(input.operation, undefined, [
        {
            path: ["evidence_output"],
            reason: "invalid_value",
            message: "Summary delivery requires --evidence_output so complete source Evidence remains available.",
        },
    ])
    : undefined;
/** One-shot delivery owns report publication; analysis keeps its own cleanup owner. */
export const deliverCliAnalysisEvidence = async (input) => {
    const { run, service, providerId, operation, signal, detail, evidenceOutput, } = input;
    const inputError = cliEvidenceDeliveryInputError(input);
    if (inputError !== undefined)
        return finishAnalysisCommand(async () => ({ ok: false, error: inputError }), service, providerId, operation, signal);
    const complete = await finishAnalysisCommand(run, service, providerId, operation, signal);
    return publishCliAnalysisEvidence(complete, {
        providerId,
        operation,
        signal,
        detail,
        evidenceOutput,
        ...(input.view === undefined ? {} : { view: input.view }),
    });
};
/** Publish already finalized CLI analysis without opening a second provider/session. */
export const publishCliAnalysisEvidence = async (value, input) => {
    const { providerId, operation, signal, detail, evidenceOutput } = input;
    if (!isEvidence(value))
        return value;
    const complete = parseEvidence(value);
    const inputError = cliEvidenceDeliveryInputError(input);
    if (inputError !== undefined) {
        inputError.retainPartialObservation(complete);
        return projectAnalysisError(inputError);
    }
    if (evidenceOutput === undefined)
        return complete;
    const resources = new ArtifactResourceScope();
    let receipt;
    const delivered = await finishAnalysisCommand(async () => {
        const written = await writeEvidenceBundle(createEvidenceBundle([
            ...new Map([...(input.sourceEvidence ?? []), complete].map((record) => [
                record.evidence_id,
                record,
            ])).values(),
        ]), absoluteCallerPath(evidenceOutput), false, resources, signal);
        if (!written.ok) {
            if (written.error.partialObservation === undefined)
                written.error.retainPartialObservation(complete);
            return written;
        }
        receipt = written.value;
        return detail === "summary"
            ? inspectAnalysisView({
                source: { kind: "inline", evidence: complete },
                view: input.view ?? { kind: "summary" },
            })
            : { ok: true, value: complete };
    }, { close: () => resources.close() }, providerId, operation, signal);
    return isEvidence(delivered) && detail === "summary"
        ? { summary: delivered, evidence_bundle: receipt }
        : delivered;
};
