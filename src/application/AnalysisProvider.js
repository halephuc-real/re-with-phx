import { createEvidence, } from "../domain/evidence.js";
import { jsonObjectSchema, jsonValueSchema } from "../domain/jsonValue.js";
import { relationshipCoverageSchema, } from "../domain/relationshipCoverage.js";
export function createAnalysisExecution(result, provider, options = {}) {
    return {
        result: jsonValueSchema.parse(result),
        rawResult: options.rawResult === undefined
            ? null
            : jsonValueSchema.parse(options.rawResult),
        provider,
        ...(options.cachePolicy === undefined
            ? {}
            : { cachePolicy: options.cachePolicy }),
        ...(options.analysisProfile === undefined
            ? {}
            : { analysisProfile: structuredClone(options.analysisProfile) }),
        limitations: [...(options.limitations ?? [])],
        ...(options.relationshipCoverage === undefined
            ? {}
            : {
                relationshipCoverage: relationshipCoverageSchema.parse(options.relationshipCoverage),
            }),
        ...(options.referencesTruncated === undefined
            ? {}
            : { referencesTruncated: options.referencesTruncated }),
        locations: [...(options.locations ?? [])],
        ...(options.subject === undefined ? {} : { subject: options.subject }),
    };
}
/**
 * Compose one completed provider execution into its caller-visible Evidence,
 * so success and a late cancellation that retains it carry identical facts.
 */
export const createAnalysisExecutionEvidence = (operation, input, execution, confidence) => createEvidence(execution.subject === undefined
    ? undefined
    : (execution.subject ?? undefined), execution.provider, {
    operation,
    parameters: jsonObjectSchema.parse(input),
    result: execution.result,
    rawResult: execution.rawResult,
    limitations: execution.limitations,
    ...(execution.analysisProfile === undefined
        ? {}
        : { analysisProfile: execution.analysisProfile }),
    ...(execution.relationshipCoverage === undefined
        ? {}
        : { relationshipCoverage: execution.relationshipCoverage }),
    locations: execution.locations,
    confidence,
});
