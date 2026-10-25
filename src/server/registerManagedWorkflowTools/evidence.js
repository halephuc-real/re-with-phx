import { parseEvidence } from "../../domain/evidence.js";
import { EvidenceIntegrityError } from "../../domain/evidenceErrors.js";
import { err, ok } from "../../domain/result.js";
/**
 * Authenticate caller-supplied records. When `expectedOperations` is omitted,
 * the shared workflow owns which authentic operations it can use.
 */
const parseExpectedEvidence = (rawEvidence, expectedOperations) => {
    try {
        const evidence = rawEvidence.map(parseEvidence);
        if (expectedOperations !== undefined)
            for (const record of evidence)
                if (!expectedOperations.includes(record.operation) ||
                    record.predicate_type !== "phxre.analysis")
                    throw new TypeError(`Expected ${expectedOperations.join(" or ")} Evidence, received ${record.operation}`);
        return ok(evidence);
    }
    catch (cause) {
        return err(new EvidenceIntegrityError(cause instanceof Error ? cause.message : "Invalid Evidence"));
    }
};
export const resolveManagedEvidence = (evidence) => parseExpectedEvidence([evidence], ["inspect_managed_members"]);
export const resolveManagedArtifactEvidence = (evidence) => parseExpectedEvidence([evidence], ["inspect_managed_artifact"]);
export const resolveManagedBoundaryEvidence = (evidence) => parseExpectedEvidence([evidence], ["inspect_managed_native_boundaries"]);
/**
 * Authenticate native observations without an operation allowlist: the domain
 * counts authentic operations it cannot read symbols from as unsupported.
 */
export const resolveNativeEvidence = (evidence) => parseExpectedEvidence(evidence);
export const sourceEvidence = (input) => [
    input.managed_artifact,
    input.managed_members,
    input.managed_native_boundaries,
].filter((evidence) => evidence !== undefined);
