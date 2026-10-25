import type { Evidence } from "./evidence.js";
import {
  PROCESS_PROVIDER,
  isProcessEvidenceProvider,
} from "./process/processEvidenceProvider.js";

/** Canonical provider identity for deterministic artifact comparisons. */
export const ARTIFACT_COMPARISON_PROVIDER = {
  id: "phxre-artifact-comparison",
  name: "PhxRE artifact comparison",
  version: "1",
} as const;

/** Canonical provider identity for deterministic function comparisons. */
export const FUNCTION_COMPARISON_PROVIDER = {
  id: "phxre-function-comparison",
  name: "PhxRE function comparison",
  version: "1",
} as const;

const COMPARISON_EVIDENCE_IDENTITIES = {
  compare_artifacts: {
    predicate: "phxre.artifact-comparison",
    provider: ARTIFACT_COMPARISON_PROVIDER,
  },
  compare_functions: {
    predicate: "phxre.function-comparison",
    provider: FUNCTION_COMPARISON_PROVIDER,
  },
  compare_process_captures: {
    predicate: "phxre.process-comparison",
    provider: PROCESS_PROVIDER,
  },
} as const;

export type ComparisonEvidenceOperation =
  keyof typeof COMPARISON_EVIDENCE_IDENTITIES;

/** Whether an operation is one of the comparison workflows this domain owns. */
export const isComparisonEvidenceOperation = (
  operation: string,
): operation is ComparisonEvidenceOperation =>
  Object.hasOwn(COMPARISON_EVIDENCE_IDENTITIES, operation);

/** Check shared Evidence identity without imposing a consumer's link policy. */
export const hasComparisonEvidenceIdentity = (evidence: Evidence): boolean => {
  if (!isComparisonEvidenceOperation(evidence.operation)) return false;
  const expected = COMPARISON_EVIDENCE_IDENTITIES[evidence.operation];
  const providerMatches =
    evidence.operation === "compare_process_captures"
      ? isProcessEvidenceProvider(evidence.provider)
      : evidence.provider.id === expected.provider.id &&
        evidence.provider.name === expected.provider.name &&
        evidence.provider.version === expected.provider.version;
  return (
    evidence.predicate_type === expected.predicate &&
    providerMatches &&
    evidence.confidence === "derived" &&
    evidence.authority === "analyst-inference" &&
    evidence.subject === null
  );
};
