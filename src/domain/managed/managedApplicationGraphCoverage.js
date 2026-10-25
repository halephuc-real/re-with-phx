import { managedTokenScopesMatch } from "./managedInspectionEvidence.js";
const omitsAny = (omissions) => omissions.partialInput ||
    omissions.unscopedTokenRelationships ||
    omissions.selectedTypes !== null;
const completeCoverage = () => ({
    status: "complete",
    truncated: false,
    omitted_count: 0,
    limits: [],
});
/** Preserve the source parser's coverage state on projected observations. */
export const managedSourceCoverage = (state) => state === "complete"
    ? completeCoverage()
    : {
        status: state,
        truncated: false,
        omitted_count: null,
        limits: [],
    };
/** Determine whether any supplied managed inspection was partial. */
export const assessManagedGraphOmissions = (sources) => ({
    unscopedTokenRelationships: sources.members !== null &&
        sources.boundaries !== null &&
        (sources.boundaries.pinvoke_imports.some(({ member_token }) => member_token !== null) ||
            sources.boundaries.native_implementations.length > 0) &&
        !managedTokenScopesMatch(sources.members.identity_scope.requires_mvid, sources.boundaries.identity_scope.requires_mvid),
    partialInput: [
        sources.members?.coverage.state,
        sources.boundaries?.coverage.state,
        sources.artifact?.coverage.state,
    ].some((state) => state !== undefined && state !== "complete"),
    selectedTypes: sources.members?.selection?.type_names ?? null,
});
/** Derive graph coverage solely from the coverage of supplied source evidence. */
export const managedGraphEvidenceCoverage = (omissions) => omitsAny(omissions)
    ? {
        status: "partial",
        truncated: false,
        omitted_count: null,
        limits: [],
    }
    : completeCoverage();
/** Report whether all supplied source evidence was complete. */
export const managedGraphResultCoverage = (omissions) => ({
    status: omitsAny(omissions)
        ? "partial"
        : "complete-within-inputs",
});
