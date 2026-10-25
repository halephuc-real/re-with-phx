import { silentLogger } from "../logger.js";
import { createEvidence } from "../domain/evidence.js";
import { ARTIFACT_ANALYSIS_OPERATIONS, } from "../contracts/artifactToolContracts.js";
import { isManagedToolName, } from "../contracts/managed/managedToolContracts.js";
import { EvidenceFileError, EvidenceIntegrityError, } from "../domain/evidenceErrors.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { access, stat } from "node:fs/promises";
import { absoluteCallerPath } from "../filesystem/callerPath.js";
import { readAnalysisSnapshot } from "./binary/AnalysisSnapshotFiles.js";
import { requiresNativeSourceAdmissionBeforeReplay } from "./binary/AnalysisSnapshotCache.js";
import { classifyBinaryTargetFilesystemFailure, parseBinaryTarget, } from "./BinaryTargetResolver.js";
import { snapshotEvidenceForQuery, snapshotMatchesTarget, } from "../domain/analysisSnapshot.js";
import { profilelessNativeDispatchProfile } from "./binary/ProfilelessNativeWorkflowSnapshot.js";
import { err, ok } from "../domain/result.js";
import { createAnalysisExecutionEvidence } from "./AnalysisProvider.js";
import { PHXRE_WORKFLOW_PROVIDER, workflowAnalysisProfile, } from "./InvestigationProviders.js";
import { executeComposedWorkflow, createWorkflowEvidence, workflowSnapshotRecord, recordWorkflowUnknowns, } from "./WorkflowEvidence.js";
import { artifactInspectionResultSchema } from "../domain/artifactInspection.js";
import { resolveXrefsAddress } from "./XrefsAddressResolution.js";
import { AnalysisInputError } from "../domain/analysisErrorCore.js";
import { directAnalysisCleanupFailure, managedAnalysisCleanupFailure, withSessionCleanup, } from "./DirectAnalysisCleanup.js";
import { BUNDLE_RESOURCE_OPERATIONS } from "./binary/BundleResourceSession.js";
// These one-shot CLI questions require native utilities, not a deep engine.
// Runtime observation retains the ordinary session and authority checks.
const NATIVE_INSPECTION_OPERATIONS = new Set([
    "inspect_macho",
    "inspect_signature",
    "list_architectures",
    "inspect_plist",
    "demangle_swift",
]);
const ARTIFACT_ANALYSIS_OPERATION_SET = new Set(ARTIFACT_ANALYSIS_OPERATIONS);
/**
 * Open one binary, execute one tool, and always release provider resources.
 * Unlike MCP mode, every CLI invocation is intentionally isolated and does not
 * retain a target or provider client for a subsequent command.
 */
export const runDirectAnalysis = async (dependencies, path, tool, arguments_, options = {}) => withProcessCancellation(options.signal, (signal) => runAnalysis(dependencies, path, tool, arguments_, {
    logger: options.logger ?? silentLogger,
    snapshotPath: options.snapshotPath,
    signal,
    ...(options.formatHint === undefined
        ? {}
        : { formatHint: options.formatHint }),
    ...(options.architecture === undefined
        ? {}
        : { architecture: options.architecture }),
    ...(options.entryPoint === undefined
        ? {}
        : { entryPoint: options.entryPoint }),
    ...(options.providerId === undefined
        ? {}
        : { providerId: options.providerId }),
}));
/** Execute one provider-native semantic operation with atomic provenance. */
export const runProviderAnalysis = async (dependencies, ...[path, tool, arguments_, logger = silentLogger, signal]) => {
    if (isManagedToolName(tool))
        return runManagedProviderAnalysis(dependencies, path, tool, arguments_, signal);
    return withProcessCancellation(signal, (operationSignal) => runAnalysis(dependencies, path, tool, arguments_, {
        logger,
        snapshotPath: undefined,
        signal: operationSignal,
        ...(ARTIFACT_ANALYSIS_OPERATION_SET.has(tool)
            ? { createSession: dependencies.createArtifactBinarySession }
            : NATIVE_INSPECTION_OPERATIONS.has(tool)
                ? { createSession: dependencies.createNativeBinarySession }
                : {}),
    }));
};
/** Execute managed metadata inspection in an isolated managed-only session. */
export const runManagedProviderExecution = async (dependencies, path, tool, signal, parameters = {}) => withProcessCancellation(signal, async (operationSignal) => {
    const session = await dependencies.createManagedBinarySession();
    return withSessionCleanup(session, async () => {
        const opened = await session.open(path, { signal: operationSignal });
        if (!opened.ok)
            return opened;
        return await session.execute(tool, parameters, {
            signal: operationSignal,
        });
    }, managedAnalysisCleanupFailure);
});
const runManagedProviderAnalysis = async (dependencies, path, tool, arguments_, signal) => {
    const execution = await runManagedProviderExecution(dependencies, path, tool, signal, arguments_);
    if (!execution.ok)
        return cliError(execution.error);
    const value = execution.value;
    return createAnalysisExecutionEvidence(tool, arguments_, value, "observed");
};
const runAnalysis = async (dependencies, path, tool, arguments_, options) => {
    const { logger, signal, snapshotPath } = options;
    let session;
    if (options.createSession !== undefined) {
        session = await options.createSession();
    }
    else {
        const config = dependencies.readConfiguration();
        if (!config.ok)
            return cliError(config.error);
        session = await (tool === "inspect_native_dispatch_metadata" && snapshotPath === undefined
            ? dependencies.createNativeDispatchBinarySession
            : dependencies.createBinarySession)(config.value, logger);
    }
    return withSessionCleanup(session, async () => {
        let isDirectory = false;
        if (BUNDLE_RESOURCE_OPERATIONS.has(tool)) {
            const inspected = await inspectBundleResourceInput(path);
            if (!inspected.ok)
                return cliError(inspected.error);
            isDirectory = inspected.value;
        }
        if (BUNDLE_RESOURCE_OPERATIONS.has(tool) && isDirectory) {
            const opened = await session.openBundleResources(path, { signal });
            if (!opened.ok)
                return cliError(opened.error);
            const execution = await session.execute(tool, arguments_, { signal });
            if (!execution.ok)
                return cliError(execution.error);
            return createAnalysisExecutionEvidence(tool, arguments_, execution.value, "observed");
        }
        const prepared = await prepareSnapshot({
            path,
            snapshotPath,
            signal,
            ...(options.formatHint === undefined
                ? {}
                : { formatHint: options.formatHint }),
            ...(options.architecture === undefined
                ? {}
                : { architecture: options.architecture }),
            ...(options.entryPoint === undefined
                ? {}
                : { entryPoint: options.entryPoint }),
        });
        if (!prepared.ok)
            return cliError(prepared.error);
        const { snapshot } = prepared.value;
        let resolvedTarget;
        if (snapshot !== undefined && prepared.value.target !== undefined) {
            const preview = await session.previewTarget(prepared.value.target, {
                signal,
                snapshot,
                ...(options.formatHint === undefined
                    ? {}
                    : { formatHint: options.formatHint }),
                ...(options.architecture === undefined
                    ? {}
                    : { architecture: options.architecture }),
                ...(options.entryPoint === undefined
                    ? {}
                    : { entryPoint: options.entryPoint }),
                ...(options.providerId === undefined
                    ? {}
                    : { providerId: options.providerId }),
            });
            if (!preview.ok)
                return cliError(preview.error);
            resolvedTarget = preview.value;
            const route = preview.value.route;
            const bindingProfile = route.profile ?? nativeDispatchBindingProfile(route, tool);
            const evidenceProfile = analysisProfileForRoute(route, tool);
            // A parsed Windows path does not prove Ghidra's native snapshot owner
            // admitted the selected source; CLI replay must wait for that client.
            if (bindingProfile !== undefined &&
                evidenceProfile !== undefined &&
                !requiresNativeSourceAdmissionBeforeReplay(route.binding?.identity.id) &&
                allowsSnapshotReplay(route, tool)) {
                const cached = snapshotEvidenceForQuery(snapshot, {
                    target: preview.value.target,
                    bindingProfile,
                    operation: tool,
                    parameters: arguments_,
                    provider: isWorkflowEvidenceTool(tool)
                        ? PHXRE_WORKFLOW_PROVIDER
                        : providerIdentityForRoute(route, tool),
                    evidenceProfile,
                });
                if (cached !== undefined)
                    return cached;
            }
        }
        const openOptions = {
            signal,
            ...(options.formatHint === undefined
                ? {}
                : { formatHint: options.formatHint }),
            ...(options.architecture === undefined
                ? {}
                : { architecture: options.architecture }),
            ...(options.entryPoint === undefined
                ? {}
                : { entryPoint: options.entryPoint }),
            ...(snapshot === undefined ? {} : { snapshot }),
            ...(options.providerId === undefined
                ? {}
                : { providerId: options.providerId }),
        };
        const opened = resolvedTarget === undefined
            ? await session.open(path, openOptions)
            : await session.openResolvedTarget(resolvedTarget, openOptions);
        if (!opened.ok)
            return cliError(opened.error);
        const evidenceProfile = analysisProfileForEvidence(session, tool);
        const { output, evidence, cachePolicy } = await executeAnalysisTool({
            session,
            openedTarget: opened.value,
            tool,
            arguments: arguments_,
            signal,
            evidenceProfile,
        });
        if (evidence !== undefined) {
            const recorded = session.recordEvidence(evidence);
            if (!recorded.ok)
                return cliError(recorded.error.retainPartialObservation(evidence));
            if (isWorkflowEvidenceTool(tool)) {
                const unknowns = recordWorkflowUnknowns({
                    name: tool,
                    result: evidence.normalized_result,
                    evidenceId: evidence.evidence_id,
                    recordUnknown: (unknown) => session.recordUnknown(unknown),
                });
                if (!unknowns.ok)
                    return cliError(unknowns.error.retainPartialObservation(evidence));
            }
        }
        if (isWorkflowEvidenceTool(tool) &&
            tool !== "trace_native_ui_action" &&
            snapshotPath !== undefined &&
            evidence !== undefined &&
            session.allowsSnapshotReplay(tool)) {
            const workflowRecord = workflowSnapshotRecord(evidence, tool, evidenceProfile, cachePolicy);
            if (workflowRecord !== undefined) {
                const recorded = session.recordWorkflowSnapshot(workflowRecord);
                if (!recorded.ok)
                    return cliError(recorded.error.retainPartialObservation(evidence));
            }
        }
        if (tool !== "trace_native_ui_action" &&
            snapshotPath !== undefined &&
            evidence !== undefined) {
            const snapshot = session.exportAnalysisSnapshot();
            if (!snapshot.ok)
                return cliError(snapshot.error.retainPartialObservation(evidence));
            const written = await session.writeAnalysisSnapshot(snapshot.value, snapshotPath, true);
            if (!written.ok) {
                const recovered = written.error instanceof EvidenceFileError &&
                    written.error.published !== undefined &&
                    (await session.closeWriteResources()).ok;
                if (!recovered)
                    return cliError(written.error.retainPartialObservation(evidence));
            }
        }
        return output;
    }, directAnalysisCleanupFailure);
};
const executeAnalysisTool = async (input) => {
    const { session, tool, signal, evidenceProfile } = input;
    if (tool === "analyze_function") {
        const { executeFunctionAnalysisEvidence } = await import("./FunctionAnalysisEvidence.js");
        const result = await executeFunctionAnalysisEvidence(session, input.arguments, input.openedTarget, { signal });
        return result.ok
            ? { output: result.value, evidence: result.value }
            : { output: cliError(result.error) };
    }
    if (tool === "binary_overview" ||
        tool === "inspect_native_api" ||
        tool === "inspect_native_dispatch_metadata" ||
        tool === "trace_feature" ||
        tool === "trace_native_values" ||
        tool === "trace_native_ui_action") {
        const { EnhancedTools } = await import("./EnhancedTools.js");
        const result = await executeComposedWorkflow(session, (observed) => new EnhancedTools(observed).execute(tool, input.arguments, signal));
        if (!result.ok)
            return { output: cliError(result.error) };
        const evidence = createWorkflowEvidence({
            target: input.openedTarget,
            operation: tool,
            parameters: input.arguments,
            result: result.value.result,
            upstreamProfile: evidenceProfile,
            upstreamLimitations: result.value.limitations,
        });
        return {
            output: evidence,
            evidence,
            ...(result.value.cachePolicy === undefined
                ? {}
                : { cachePolicy: result.value.cachePolicy }),
        };
    }
    let result = await session.execute(tool, input.arguments, { signal });
    if (tool === "xrefs" &&
        typeof input.arguments.address === "string" &&
        !result.ok &&
        result.error instanceof AnalysisInputError &&
        !result.error.cleanupIncomplete &&
        result.error.issues.length > 0 &&
        result.error.issues.every(({ path, reason }) => path.length === 1 &&
            path[0] === "address" &&
            reason === "invalid_format")) {
        const address = await resolveXrefsAddress(session, input.arguments.address, signal);
        if (!address.ok)
            return { output: cliError(address.error) };
        if (address.value !== input.arguments.address)
            result = await session.execute(tool, { ...input.arguments, address: address.value }, { signal });
    }
    if (!result.ok)
        return { output: cliError(result.error) };
    const evidence = createEvidence(result.value.subject === undefined
        ? input.openedTarget
        : (result.value.subject ?? undefined), result.value.provider, {
        operation: tool,
        parameters: input.arguments,
        result: result.value.result,
        ...(result.value.analysisProfile === undefined
            ? {}
            : { analysisProfile: result.value.analysisProfile }),
        rawResult: result.value.rawResult,
        limitations: result.value.limitations,
        ...(result.value.relationshipCoverage === undefined
            ? {}
            : { relationshipCoverage: result.value.relationshipCoverage }),
        locations: result.value.locations,
        evidenceLinks: tool === "inspect_artifact"
            ? artifactInspectionResultSchema.parse(result.value.result)
                .evidence_links
            : [],
    });
    return { output: evidence, evidence };
};
const withProcessCancellation = async (suppliedSignal, operation) => {
    if (suppliedSignal !== undefined)
        return operation(suppliedSignal);
    const controller = new AbortController();
    const cancel = () => controller.abort();
    // Package runners can forward a terminal interrupt after PhxRE already received
    // it directly. Keep both guards installed until provider cleanup has settled.
    process.on("SIGINT", cancel);
    process.on("SIGTERM", cancel);
    try {
        return await operation(controller.signal);
    }
    finally {
        process.off("SIGINT", cancel);
        process.off("SIGTERM", cancel);
    }
};
const prepareSnapshot = async (options) => {
    const { path, snapshotPath } = options;
    if (snapshotPath === undefined || !(await fileExists(snapshotPath)))
        return ok({});
    const loaded = await readAnalysisSnapshot(snapshotPath, options.signal);
    if (!loaded.ok)
        return loaded;
    const target = await parseBinaryTarget(path, {
        signal: options.signal,
        ...(options.formatHint === undefined
            ? {}
            : { formatHint: options.formatHint }),
        ...(options.architecture === undefined
            ? {}
            : { architecture: options.architecture }),
        ...(options.entryPoint === undefined
            ? {}
            : { entryPoint: options.entryPoint }),
    });
    if (!target.ok)
        return target;
    if (!snapshotMatchesTarget(loaded.value.target, target.value))
        return err(new EvidenceIntegrityError("Analysis snapshot target does not match the requested binary"));
    return ok({ snapshot: loaded.value, target: target.value });
};
const inspectBundleResourceInput = async (path) => {
    const callerPath = absoluteCallerPath(path);
    try {
        return ok((await stat(callerPath)).isDirectory());
    }
    catch (cause) {
        const failure = classifyBinaryTargetFilesystemFailure(callerPath, cause);
        if (failure !== undefined)
            return err(failure);
        throw cause;
    }
};
const allowsSnapshotReplay = (route, tool) => {
    if (tool === "trace_native_ui_action")
        return false;
    const descriptor = route.capabilities?.get(tool);
    return descriptor === undefined
        ? ![...(route.capabilities?.values() ?? [])].some(({ cachePolicy }) => cachePolicy === "live")
        : descriptor.cachePolicy !== "live";
};
const analysisProfileForRoute = (route, tool) => {
    const profile = route.profile;
    const nativeDispatchProfile = profile === null || profile === undefined
        ? nativeDispatchBindingProfile(route, tool)
        : undefined;
    if (profile === null || profile === undefined) {
        if (nativeDispatchProfile === undefined)
            return undefined;
        return isWorkflowEvidenceTool(tool)
            ? workflowAnalysisProfile(nativeDispatchProfile, tool)
            : nativeDispatchProfile;
    }
    if (isWorkflowEvidenceTool(tool))
        return workflowAnalysisProfile(profile, tool);
    const provider = providerIdentityForRoute(route, tool);
    return provider.id === profile.provider.id ? profile : undefined;
};
const nativeDispatchBindingProfile = (route, operation) => {
    if (operation !== "inspect_native_dispatch_metadata")
        return undefined;
    return profilelessNativeDispatchProfile(route);
};
/** Mirror BinarySession.providerIdentity for a route not opened yet. */
const providerIdentityForRoute = (route, operation) => route.capabilities?.get(operation)?.provider ?? route.identity;
const analysisProfileForEvidence = (session, tool) => {
    if (!isWorkflowEvidenceTool(tool))
        return session.analysisProfile(tool);
    return session.analysisProfile() ?? session.analysisProfile(tool);
};
const isWorkflowEvidenceTool = (tool) => tool === "binary_overview" ||
    tool === "inspect_native_api" ||
    tool === "inspect_native_dispatch_metadata" ||
    tool === "trace_feature" ||
    tool === "trace_native_values" ||
    tool === "trace_native_ui_action";
const fileExists = async (path) => {
    try {
        await access(path);
        return true;
    }
    catch (cause) {
        if (typeof cause === "object" &&
            cause !== null &&
            "code" in cause &&
            cause.code === "ENOENT")
            return false;
        throw cause;
    }
};
const cliError = (error) => ({
    error: "Analysis failed",
    ...projectAnalysisError(error),
});
