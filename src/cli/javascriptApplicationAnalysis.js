import { JAVASCRIPT_APPLICATION_PROVIDER } from "../application/InvestigationProviders.js";
import { createProgressReporter } from "../application/ProgressReporter.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
/**
 * One scope for every JavaScript analysis in this process. A healthy worker
 * stays parked between commands; {@link closeCliJavaScriptResources} stops it.
 * Pending cleanup is still retried before each command returns.
 */
let retainedScope;
/** One shutdown shared by the exit callback and the dispatch `finally`. */
let closing;
const cliAnalysisScope = () => {
    retainedScope ??= new ArtifactResourceScope();
    return retainedScope;
};
/**
 * Stop the process-owned JavaScript worker. Callers that overlap share the
 * attempt in flight. The scope stays owned when shutdown fails, so the next
 * call retries instead of treating the worker as already released.
 */
export const closeCliJavaScriptResources = () => {
    if (closing !== undefined)
        return closing;
    const scope = retainedScope;
    if (scope === undefined)
        return Promise.resolve();
    let published;
    published = scope
        .close()
        .then(() => {
        if (retainedScope === scope)
            retainedScope = undefined;
    })
        .finally(() => {
        if (closing === published)
            closing = undefined;
    });
    closing = published;
    return published;
};
/** Execute the shared CLI boundary for static JavaScript analysis. */
export const runCliJavaScriptApplicationAnalysis = async (input, signal) => {
    const { analyzeJavaScriptApplication } = await import("../application/javascript/JavaScriptApplicationService.js");
    const progress = createProgressReporter(async (update) => {
        process.stderr.write(`${JSON.stringify({ phxre_progress: update })}\n`);
    }, { minimumIntervalMs: 0 });
    const resources = cliAnalysisScope();
    const result = await analyzeJavaScriptApplication(input, resources, {
        progress,
        ...(signal === undefined ? {} : { signal }),
    });
    try {
        // Retry failed owners without stopping a healthy parked worker.
        await resources.retryCleanup();
    }
    catch (cause) {
        const cleanup = ArtifactReaderFailure.cleanupObservation(cause, "JavaScript application resources");
        const failure = new ProviderCleanupError(JAVASCRIPT_APPLICATION_PROVIDER.id, cleanup.resources, { reason: cleanup.reason }, { cause, operation: "analyze_javascript_application" });
        return cliError(result.ok
            ? failure
            : analysisErrorWithCleanupFailure(result.error, failure, "analyze_javascript_application"));
    }
    return result.ok ? result.value : cliError(result.error);
};
const cliError = (error) => ({
    error: "JavaScript application analysis failed",
    ...projectAnalysisError(error),
});
