import { realpath } from "node:fs/promises";
import { artifactInventoryResultSchema, } from "../../domain/artifactGraph.js";
import { abortIfNeeded } from "../ArtifactHash.js";
import { scanCanonicalArtifactInventoryInScope } from "./scanCanonical.js";
/** Inventory one local artifact and return every graph collection inline. */
export const inventoryArtifact = async (inputPath, options) => {
    const snapshot = await scanArtifactInventory(inputPath, options);
    return artifactInventoryResultSchema.parse(snapshot);
};
/** Scan an artifact once and retain the complete immutable graph for projection. */
export const scanArtifactInventory = async (inputPath, options) => options.resourceScope.run(() => scanArtifactInventoryInScope(inputPath, options));
export const scanArtifactInventoryInScope = async (inputPath, options) => {
    abortIfNeeded(options.signal);
    const path = await realpath(inputPath);
    return scanCanonicalArtifactInventoryInScope(path, options);
};
