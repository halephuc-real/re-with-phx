import { resolve } from "node:path";
import { z } from "zod";
import { AnalysisProtocolError } from "../../domain/analysisErrorCore.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { parseRuntimeReconciliationInput, reconcileJavaScriptRuntime, } from "../../domain/javascript/javascriptRuntimeReconciliation.js";
import { reconcileJavaScriptRuntimeInputSchema } from "../../domain/javascript/javascriptRuntimeReconciliationSchemas.js";
import { err, ok } from "../../domain/result.js";
import { createJavaScriptRuntimeReconciliationEvidence } from "./JavaScriptRuntimeReconciliationEvidence.js";
const OPERATION = "reconcile_javascript_runtime";
/** Derive a combined JAG from verified static and passive-runtime Evidence. */
export const reconcileJavaScriptRuntimeEvidence = (rawInput) => {
    const parsed = reconcileJavaScriptRuntimeInputSchema.safeParse(rawInput);
    if (!parsed.success)
        return err(analysisInputErrorFromIssues(OPERATION, parsed.error.issues, rawInput));
    return reconcileJavaScriptRuntimeEvidenceValidated(parsed.data);
};
/** Reconcile input already parsed by a trusted adapter boundary. */
export const reconcileJavaScriptRuntimeEvidenceValidated = (parsedInput) => {
    let parsed;
    try {
        parsed = parseRuntimeReconciliationInput(normalizeRuntimeMappingRoots(parsedInput));
    }
    catch (cause) {
        if (cause instanceof z.ZodError)
            return err(analysisInputErrorFromIssues(OPERATION, cause.issues, parsedInput));
        return err(new AnalysisProtocolError("JavaScript runtime reconciliation input parsing failed", { cause }));
    }
    try {
        const result = reconcileJavaScriptRuntime(parsed);
        return ok(createJavaScriptRuntimeReconciliationEvidence(parsed.input, result));
    }
    catch (cause) {
        return err(new AnalysisProtocolError("JavaScript runtime reconciliation produced an invalid result", { cause }));
    }
};
const normalizeRuntimeMappingRoots = (input) => ({
    ...input,
    static_layers: input.static_layers.map((layer) => ({
        ...layer,
        runtime_mappings: layer.runtime_mappings.map((mapping) => mapping.kind === "file-root"
            ? {
                ...mapping,
                root: isPortableAbsolutePath(mapping.root)
                    ? mapping.root
                    : resolve(mapping.root),
            }
            : mapping),
    })),
});
const isPortableAbsolutePath = (path) => path.startsWith("/") ||
    /^[a-z]:[\\/]/iu.test(path) ||
    /^(?:\\\\|\/\/)[^\\/]+[\\/][^\\/]+(?:[\\/]|$)/u.test(path);
