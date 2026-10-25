/** Provider identity for deterministic composed analysis workflows. */
export const PHXRE_WORKFLOW_PROVIDER = {
  id: "phxre-workflow",
  name: "PhxRE composed investigation workflow",
  version: "1",
} as const;

/** Provider identity for deterministic artifact inventories. */
export const ARTIFACT_GRAPH_PROVIDER = Object.freeze({
  id: "phxre-artifact-graph",
  name: "PhxRE safe artifact graph provider",
  version: "1",
} as const);

/** Provider identity for execution-free managed PE/CLI analysis. */
export const MANAGED_STATIC_PROVIDER = Object.freeze({
  id: "phxre-dotnet-static",
  name: "PhxRE managed static analysis provider",
  version: "1",
} as const);

/** Provider identity for portable, execution-free PE resource decoding. */
export const PE_RESOURCES_PROVIDER = Object.freeze({
  id: "phxre-pe-resources",
  name: "PhxRE PE resource parser",
  version: "1",
} as const);

/** Provider identity for portable, execution-free PE Authenticode table decoding. */
export const PE_CERTIFICATES_PROVIDER = Object.freeze({
  id: "phxre-pe-certificates",
  name: "PhxRE PE certificate parser",
  version: "1",
} as const);

/** Provider identity for portable, execution-free PE import-table decoding. */
export const PE_IMPORTS_PROVIDER = Object.freeze({
  id: "phxre-pe-imports",
  name: "PhxRE PE import parser",
  version: "1",
} as const);

/** Provider identity for portable, execution-free ELF note-table decoding. */
export const DEVICETREE_PROVIDER = Object.freeze({
  id: "phxre-devicetree",
  name: "PhxRE flattened devicetree parser",
  version: "1",
} as const);

export const ELF_NOTES_PROVIDER = Object.freeze({
  id: "phxre-elf-notes",
  name: "PhxRE ELF note parser",
  version: "1",
} as const);

/** Provider identity for portable, execution-free Apple .ips crash-report decoding. */
export const APPLE_IPS_PROVIDER = Object.freeze({
  id: "phxre-apple-ips",
  name: "PhxRE Apple IPS parser",
  version: "1",
} as const);
/** Provider identity for portable, execution-free Linux kernel-module metadata. */
export const KERNEL_MODULE_PROVIDER = Object.freeze({
  id: "phxre-kernel-module",
  name: "PhxRE kernel module parser",
  version: "1",
} as const);

/** Provider identity for execution-free Shannon byte-entropy profiling. */
export const BYTE_ENTROPY_PROVIDER = Object.freeze({
  id: "byte-entropy",
  name: "PhxRE byte entropy",
  version: "1",
} as const);

/** Provider identity for portable, execution-free PE and ELF export tables. */
export const NATIVE_EXPORTS_PROVIDER = Object.freeze({
  id: "phxre-native-exports",
  name: "PhxRE PE/ELF export table reader",
  version: "1",
} as const);

/** Provider identity for deterministic managed-code comparison workflows. */
export const MANAGED_WORKFLOW_PROVIDER = {
  id: "phxre-dotnet-workflows",
  name: "PhxRE managed-code workflows",
  version: "1",
} as const;

/** Provider identity for deterministic Apple application projections. */
export const APPLE_APPLICATION_PROVIDER = {
  id: "phxre-apple-application",
  name: "PhxRE Apple application workflows",
  version: "1",
} as const;

/** Provider identity for deterministic Android application projections. */
export const ANDROID_APPLICATION_PROVIDER = {
  id: "phxre-android-application",
  name: "PhxRE Android application workflows",
  version: "1",
} as const;

/** Provider identity for deterministic HarmonyOS application projections. */
export const HARMONY_APPLICATION_PROVIDER = {
  id: "phxre-harmony-application",
  name: "PhxRE HarmonyOS application workflows",
  version: "1",
} as const;

/** Provider identity for verified publication of retained website scripts. */
export const WEB_SCRIPT_EXPORT_PROVIDER = {
  id: "phxre-web-script-export",
  name: "PhxRE captured script export",
  version: "1",
} as const;

/** Provider identity for deterministic static JavaScript application analysis. */
export const JAVASCRIPT_APPLICATION_PROVIDER = {
  id: "phxre-javascript-application",
  name: "PhxRE JavaScript application analyzer",
  version: "1",
} as const;

/** Provider identity for static/passive-runtime JavaScript reconciliation. */
export const JAVASCRIPT_RUNTIME_RECONCILIATION_PROVIDER = {
  id: "phxre-javascript-runtime-reconciliation",
  name: "PhxRE JavaScript runtime reconciliation",
  version: "1",
} as const;

/** Provider identity for selected views of retained analysis Evidence. */
export const ANALYSIS_VIEW_PROVIDER = {
  id: "phxre-analysis-view",
  name: "PhxRE analysis view projection",
  version: "1",
} as const;

/** Provider identity for graph-native feature tracing and version comparison. */
export const JAVASCRIPT_APPLICATION_WORKFLOW_PROVIDER = {
  id: "phxre-javascript-application-workflows",
  name: "PhxRE JavaScript application workflows",
  version: "1",
} as const;

/** Provider identity for deterministic Evidence bundle comparisons. */
export const BUNDLE_COMPARISON_PROVIDER = {
  id: "phxre-bundle-comparison",
  name: "PhxRE Evidence bundle comparison",
  version: "1",
} as const;

/** Provider identity for comparison-Evidence behavior aggregation. */
export const CHANGED_BEHAVIOR_PROVIDER = {
  id: "phxre-changed-behavior",
  name: "PhxRE changed behavior investigation",
  version: "1",
} as const;

/** Provider identity for Evidence-backed call-path reconstruction. */
export const CALL_PATH_PROVIDER = {
  id: "phxre-call-path",
  name: "PhxRE call path reconstruction",
  version: "1",
} as const;

/** Provider identity for explicit static/runtime hypothesis correlation. */
export const STATIC_RUNTIME_PROVIDER = {
  id: "phxre-static-runtime-correlation",
  name: "PhxRE static/runtime correlation",
  version: "1",
} as const;

/** Provider identity for finite reconstruction specification verification. */
export const RECONSTRUCTION_PROVIDER = {
  id: "phxre-reconstruction-verifier",
  name: "PhxRE reconstruction verifier",
  version: "1",
} as const;

export const PE_LOAD_CONFIG_PROVIDER = Object.freeze({
  id: "phxre-pe-load-config",
  name: "PhxRE PE TLS/load-config parser",
  version: "1",
} as const);
