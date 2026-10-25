import { satisfies } from "semver";
/** Supported runtime range, kept in sync with the published package engines. */
export const SUPPORTED_NODE_VERSION_RANGE = "^22.19.0 || ^24.11.0 || >=26.0.0";
/** Human-readable form of {@link SUPPORTED_NODE_VERSION_RANGE} for remediation. */
export const SUPPORTED_NODE_VERSION_PROSE = "Node.js 22.x (>=22.19), 24.x (>=24.11), or 26+";
/** Return whether a Node.js version satisfies PhxRE's tested runtime families. */
export const supportsNodeVersion = (version) => satisfies(version, SUPPORTED_NODE_VERSION_RANGE);
/** Identify the runtime from `process.versions`; only Bun reports `bun`. */
export const javaScriptRuntime = (versions) => versions.bun === undefined
    ? { id: "node", version: versions.node }
    : {
        id: "bun",
        version: versions.bun,
        nodeCompatibilityVersion: versions.node,
    };
