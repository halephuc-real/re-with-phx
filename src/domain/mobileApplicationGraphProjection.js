import { createHash } from "node:crypto";
import canonicalize from "canonicalize";
import { z } from "zod";
import { hasCompleteInventoryCoverage, } from "./artifactInventoryEvidence.js";
import { evidenceSchema } from "./evidence.js";
import { digestSchema } from "./digests.js";
import { prefixedDigestSchema } from "./digests.js";
import { bridgeCandidateCoverageSchema, projectCartesianCandidates, } from "./bridgeCandidateProjection.js";
/** Evidence-scoped identifier schemas shared by application graph projections. */
export const projectionEvidenceIdSchema = prefixedDigestSchema("ev");
export const projectionPathSchema = z.string().min(1);
/** Inventory pages accepted by every application graph projection. */
export const applicationInventoryProjectionInputSchema = z.strictObject({
    inventory_evidence: z.array(evidenceSchema).min(1),
});
/** One authenticated inventory entry retained by application graph projections. */
export const projectedComponentSchema = z.strictObject({
    path: projectionPathSchema,
    artifact_id: prefixedDigestSchema("art"),
    sha256: digestSchema,
    format: z.string().min(1),
});
/** Inventoried paths whose content identity is unavailable, retained as unknown. */
export const unavailableComponentSchema = z.strictObject({
    path: projectionPathSchema,
    artifact_id: z.null(),
    sha256: z.null(),
    format: z.string().min(1),
    encrypted: z.boolean(),
    limitations: z.array(z.string()),
});
/** Path-pair hypotheses connecting managed content to a native library. */
export const projectedBridgeCandidateSchema = (basis) => z.strictObject({
    managed_path: projectionPathSchema,
    native_path: projectionPathSchema,
    basis: z.enum(basis),
});
/** Coverage status combining inventory completeness with a projection budget. */
export const projectionCoverage = (inventory, budgetComplete) => ({
    status: hasCompleteInventoryCoverage(inventory, "container-entries") &&
        budgetComplete
        ? "complete-within-inventory"
        : "partial",
    inventory_complete: inventory.complete,
});
/** Interpret identity once, before application-specific attribution and classification. */
export const projectedInventoryEntries = (inventory) => {
    const nodes = new Map(inventory.nodes.map((node) => [node.artifact_id, node]));
    return inventory.occurrences
        .filter(({ logical_path }) => logical_path !== ".")
        .map((occurrence) => {
        const path = occurrence.logical_path;
        const kind = occurrence.entry_kind;
        if (occurrence.artifact_id === null)
            return {
                path,
                kind,
                component: undefined,
                unavailable: {
                    path,
                    artifact_id: null,
                    sha256: null,
                    format: occurrence.artifact_format,
                    encrypted: occurrence.encrypted,
                    limitations: occurrence.limitations,
                },
            };
        const node = nodes.get(occurrence.artifact_id);
        if (node === undefined)
            throw new TypeError("Application projection occurrence has no artifact node");
        return {
            path,
            kind,
            component: {
                path,
                artifact_id: node.artifact_id,
                sha256: node.sha256,
                format: occurrence.artifact_format,
            },
            unavailable: undefined,
        };
    });
};
/** Directory trees and links retain inventory identity but are not file components. */
export const projectedFileComponents = (entries) => entries.flatMap(({ kind, component }) => (kind === "file" || kind === "slice") && component !== undefined
    ? [component]
    : []);
export { bridgeCandidateCoverageSchema, projectCartesianCandidates };
/** Digest a canonical JSON projection payload for its stable identifier. */
export const projectionDigest = (value, label) => {
    const encoded = canonicalize(value);
    if (encoded === undefined)
        throw new TypeError(`${label} is not canonical JSON`);
    return createHash("sha256").update(encoded).digest("hex");
};
