/** Required packaged sources, selected by their runtime role rather than order. */
export const GHIDRA_BRIDGE_SOURCES = Object.freeze({
  bridge: "PhxReGhidraBridge.java",
  bundleActivator: "PhxReGhidraBundleActivator.java",
  extensions: "PhxReGhidraExtensions.java",
  prepareCom: "PhxReGhidraPrepareCom.java",
  prepareRaw: "PhxReGhidraPrepareRaw.java",
  prepareDol: "PhxReGhidraPrepareDol.java",
  applySeeds: "PhxReGhidraApplySeeds.java",
  analysisOptions: "PhxReGhidraAnalysisOptions.java",
  noReturnFix: "PhxReGhidraNoReturnFix.java",
  mipsSoftFloat: "PhxReGhidraMipsSoftFloat.java",
} as const);
