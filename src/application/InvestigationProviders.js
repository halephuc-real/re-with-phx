import { createAnalysisProfile, } from "../domain/analysisProfile.js";
/** Provider identity for deterministic composed analysis workflows. */
export const PHXRE_WORKFLOW_PROVIDER = {
    id: "phxre-workflow",
    name: "PhxRE composed investigation workflow",
    version: "1",
};
/** Commit a workflow result to its upstream profile and applicable semantic revision. */
export const workflowAnalysisProfile = (upstream, operation) => createAnalysisProfile(PHXRE_WORKFLOW_PROVIDER, {
    upstream_analysis_profile: upstream,
    source_limitations: "provider-operation-caveats-v1",
    ...(operation === "binary_overview"
        ? { workflow_revision: 4 }
        : operation === "batch_decompile" ||
            operation === "get_call_graph" ||
            operation === "trace_feature"
            ? { workflow_revision: 3 }
            : { workflow_revision: 1 }),
});
/** Provider identity for deterministic artifact inventories. */
export const ARTIFACT_GRAPH_PROVIDER = Object.freeze({
    id: "phxre-artifact-graph",
    name: "PhxRE safe artifact graph provider",
    version: "1",
});
/** Provider identity for execution-free managed PE/CLI analysis. */
export const MANAGED_STATIC_PROVIDER = Object.freeze({
    id: "phxre-dotnet-static",
    name: "PhxRE managed static analysis provider",
    version: "1",
});
/** Provider identity for portable, execution-free PE resource decoding. */
export const PE_RESOURCES_PROVIDER = Object.freeze({
    id: "phxre-pe-resources",
    name: "PhxRE PE resource parser",
    version: "1",
});
/** Provider identity for deterministic managed-code comparison workflows. */
export const MANAGED_WORKFLOW_PROVIDER = {
    id: "phxre-dotnet-workflows",
    name: "PhxRE managed-code workflows",
    version: "1",
};
/** Provider identity for deterministic Apple application projections. */
export const APPLE_APPLICATION_PROVIDER = {
    id: "phxre-apple-application",
    name: "PhxRE Apple application workflows",
    version: "1",
};
/** Provider identity for deterministic Android application projections. */
export const ANDROID_APPLICATION_PROVIDER = {
    id: "phxre-android-application",
    name: "PhxRE Android application workflows",
    version: "1",
};
/** Provider identity for deterministic HarmonyOS application projections. */
export const HARMONY_APPLICATION_PROVIDER = {
    id: "phxre-harmony-application",
    name: "PhxRE HarmonyOS application workflows",
    version: "1",
};
/** Provider identity for verified publication of retained website scripts. */
export const WEB_SCRIPT_EXPORT_PROVIDER = {
    id: "phxre-web-script-export",
    name: "PhxRE captured script export",
    version: "1",
};
/** Provider identity for deterministic static JavaScript application analysis. */
export const JAVASCRIPT_APPLICATION_PROVIDER = {
    id: "phxre-javascript-application",
    name: "PhxRE JavaScript application analyzer",
    version: "1",
};
/** Provider identity for static/passive-runtime JavaScript reconciliation. */
export const JAVASCRIPT_RUNTIME_RECONCILIATION_PROVIDER = {
    id: "phxre-javascript-runtime-reconciliation",
    name: "PhxRE JavaScript runtime reconciliation",
    version: "1",
};
/** Provider identity for selected views of retained analysis Evidence. */
export const ANALYSIS_VIEW_PROVIDER = {
    id: "phxre-analysis-view",
    name: "PhxRE analysis view projection",
    version: "1",
};
/** Provider identity for graph-native feature tracing and version comparison. */
export const JAVASCRIPT_APPLICATION_WORKFLOW_PROVIDER = {
    id: "phxre-javascript-application-workflows",
    name: "PhxRE JavaScript application workflows",
    version: "1",
};
/** Provider identity for deterministic cross-artifact comparisons. */
export const ARTIFACT_COMPARISON_PROVIDER = {
    id: "phxre-artifact-comparison",
    name: "PhxRE artifact comparison",
    version: "1",
};
/** Provider identity for deterministic cross-function comparisons. */
export const FUNCTION_COMPARISON_PROVIDER = {
    id: "phxre-function-comparison",
    name: "PhxRE function comparison",
    version: "1",
};
/** Provider identity for deterministic Evidence bundle comparisons. */
export const BUNDLE_COMPARISON_PROVIDER = {
    id: "phxre-bundle-comparison",
    name: "PhxRE Evidence bundle comparison",
    version: "1",
};
/** Provider identity for comparison-Evidence behavior aggregation. */
export const CHANGED_BEHAVIOR_PROVIDER = {
    id: "phxre-changed-behavior",
    name: "PhxRE changed behavior investigation",
    version: "1",
};
/** Provider identity for Evidence-backed call-path reconstruction. */
export const CALL_PATH_PROVIDER = {
    id: "phxre-call-path",
    name: "PhxRE call path reconstruction",
    version: "1",
};
/** Provider identity for explicit static/runtime hypothesis correlation. */
export const STATIC_RUNTIME_PROVIDER = {
    id: "phxre-static-runtime-correlation",
    name: "PhxRE static/runtime correlation",
    version: "1",
};
/** Provider identity for finite reconstruction specification verification. */
export const RECONSTRUCTION_PROVIDER = {
    id: "phxre-reconstruction-verifier",
    name: "PhxRE reconstruction verifier",
    version: "1",
};
