import { createGpuCodeObjectsService } from "../composition/gpu.js";
import { registerGpuCodeObjectsTools } from "./registerGpuCodeObjectsTools.js";
import { UNTRUSTED_CONTENT_INSTRUCTIONS } from "./toolResultEncoding.js";
import { createPacketCaptureService } from "../composition/captures.js";
import { registerCaptureTools } from "./registerCaptureTools.js";
import { createSignalRecordingService } from "../composition/signals.js";
import { registerSignalTools } from "./registerSignalTools.js";
import { wasmArtifactModule } from "../composition/wasm.js";
import { registerWasmTools } from "./registerWasmTools.js";
import { snapshotEnvironment } from "../process/snapshotEnvironment.js";
import { captureProviderEnvironment } from "./providerEnvironment.js";
import { createPeResourcesService } from "../composition/binaryDiagnostics.js";
import { registerPeResourcesTool } from "./registerPeResourcesTool.js";
import { evmInterfaceModule, evmLimiterAvailability, } from "../composition/evm.js";
import { registerEvmTools } from "./registerEvmTools.js";
import { createSqliteDatabaseService } from "../composition/sqlite.js";
import { registerSqliteTools } from "./registerSqliteTools.js";
import { registerRecordedCrashTools } from "./registerRecordedCrashTools.js";
import { createRecordedCrashService } from "../composition/binaryDiagnostics.js";
import { createDesktopApplicationService } from "../composition/desktop.js";
import { registerDesktopApplicationTool } from "./registerDesktopApplicationTool.js";
import { createGoBinaryService } from "../composition/go.js";
import { createModelArtifactService } from "../composition/model.js";
import { registerModelArtifactTools } from "./registerModelArtifactTools.js";
import { createIl2cppMetadataService } from "../composition/il2cpp.js";
import { createElectronFuseService } from "../composition/electronFuses.js";
import { registerGoTools } from "./registerGoTools.js";
import { registerIl2cppTools } from "./registerIl2cppTools.js";
import { createRustBinaryService } from "../composition/rust.js";
import { registerRustTools } from "./registerRustTools.js";
import { registerAnalysisViewTool } from "./registerAnalysisViewTool.js";
import { registerBinaryDiagnosticsTools } from "./registerBinaryDiagnosticsTools.js";
import { FridaInstrumentationManager } from "../frida/FridaInstrumentationManager.js";
import { registerFridaTools } from "./registerFridaTools.js";
import { createBinaryLayoutService } from "../composition/binaryDiagnostics.js";
import { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import { createToolResultDelivery, } from "./toolResult.js";
import { parseMcpResponseBudget } from "../config/mcpResponseBudget.js";
import { parseMcpOutputSchemaProfile } from "../config/mcpOutputSchemaProfile.js";
import { compactPresentationForMcpInputSchemaProfile, parseMcpInputSchemaProfile, } from "../config/mcpInputSchemaProfile.js";
import { isAbsolute } from "node:path";
import { PRODUCT_IDENTITY } from "../identity.js";
import { silentLogger } from "../logger.js";
import { registerApplicationTools } from "./registerApplicationTools.js";
import { registerArtifactTools } from "./registerArtifactTools.js";
import { registerNativeTools } from "./registerNativeTools.js";
import { registerBrowserScenarioTool } from "./registerBrowserScenarioTool.js";
import { registerBrowserTools } from "./registerBrowserTools.js";
import { registerWebScriptTool } from "./registerWebScriptTool.js";
import { registerWebModuleTool } from "./registerWebModuleTool.js";
import { createWebModuleTraceService } from "../composition/webModules.js";
import { createWebSourceLocationService } from "../composition/webSourceLocations.js";
import { registerWebSourceLocationTool } from "./registerWebSourceLocationTool.js";
import { createWebRuntimeService } from "../composition/webRuntime.js";
import { registerWebRuntimeTools } from "./registerWebRuntimeTools.js";
import { createWebNetworkCaptureService } from "../composition/webNetworkCaptures.js";
import { registerWebNetworkCaptureTool } from "./registerWebNetworkCaptureTool.js";
import { registerJavaScriptRecoveryTool } from "./registerJavaScriptRecoveryTool.js";
import { JavaScriptRecoveryService } from "../application/javascript/JavaScriptRecoveryService.js";
import { createJavaScriptRecoveryProvider } from "../composition/javascriptRecovery.js";
import { registerElectronTools } from "./registerElectronTools.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { registerEnhancedTools } from "./registerEnhancedTools.js";
import { registerJavaScriptRuntimeObservationTools } from "./registerJavaScriptRuntimeObservationTools.js";
import { registerManagedTools } from "./registerManagedTools.js";
import { registerFirmwareTools } from "./registerFirmwareTools.js";
import { FirmwareAnalysisService } from "../application/firmware/FirmwareAnalysisService.js";
import { createFirmwareAnalysisProvider } from "../composition/firmware.js";
import { registerAndroidTools } from "./registerAndroidTools.js";
import { registerApktoolTools } from "./registerApktoolTools.js";
import { registerPcapTools } from "./registerPcapTools.js";
import { registerFlutterTools } from "./registerFlutterTools.js";
import { registerJebTools } from "./registerJebTools.js";
import { registerAdbTools } from "./registerAdbTools.js";
import { AndroidAnalysisService } from "../application/android/AndroidAnalysisService.js";
import { JebAnalysisService } from "../application/jeb/JebAnalysisService.js";
import { PcapAnalysisService } from "../application/pcap/PcapAnalysisService.js";
import { ApktoolResourceAnalysisService } from "../application/apktool/ApktoolResourceAnalysisService.js";
import { FlutterBuildAnalysisService } from "../application/flutter/FlutterBuildAnalysisService.js";
import { createAndroidAnalysisProvider } from "../composition/android.js";
import { createApktoolResourceAnalysisProvider } from "../composition/apktool.js";
import { createPcapAnalysisProvider } from "../composition/pcap.js";
import { createFlutterBuildAnalysisProvider } from "../composition/flutter.js";
import { createJebAnalysisProvider } from "../composition/jeb.js";
import { AdbDeviceAnalysisService } from "../application/adb/AdbDeviceAnalysisService.js";
import { createAdbDeviceAnalysisProvider } from "../composition/adb.js";
import { registerManagedWorkflowTools } from "./registerManagedWorkflowTools.js";
import { registerOfficialTools } from "./registerOfficialTools.js";
import { registerGuidedPrompts } from "./registerPrompts.js";
import { registerSessionTools } from "./registerSessionTools.js";
import { sessionAvailabilityPolicy } from "./sessionAvailabilityPolicy.js";
import { withAdmittedAnalysis, } from "./analysisAdmission.js";
import { createReverseEngineeringService } from "../composition/reverseEngineering.js";
import { registerReverseEngineeringTools } from "./registerReverseEngineeringTools.js";
import { CutterBridgeClient } from "../cutter/CutterBridgeClient.js";
import { CutterBridgeService } from "../cutter/CutterBridgeService.js";
import { registerCutterTools } from "./registerCutterTools.js";
import { GdbSessionManager } from "../gdb/GdbSessionManager.js";
import { registerGdbTools } from "./registerGdbTools.js";
import { RizinDebugSessionManager } from "../rizin/RizinDebugSessionManager.js";
import { registerRizinDebugTools } from "./registerRizinDebugTools.js";
const TARGET_FREE_INSTRUCTIONS = "PhxRE provides reverse-engineering tools for local artifacts, native binaries, managed code, browser pages, and runtimes. Use the tool that directly answers the question; discover targets or inspect inventory only when needed. Tool results include inline Evidence and report their coverage and limitations. An opened target persists across turns. When finished, export needed Evidence and call close_binary; its snapshot_path can retain analysis.";
const ACTIVE_TARGET_INSTRUCTIONS = "PhxRE analyzes the active reverse-engineering target. Use the analysis tool that answers the question directly. Search or list symbols when discovery is needed; analyze_function provides a function dossier, and focused procedure tools return individual facets.";
// A host deadline can discard the response before error remediation reaches the
// agent. Teach that distinction at initialization, not just in returned errors.
const RECOVERY_INSTRUCTIONS = "Recovery: For invalid arguments, read the connected tool's input schema (refresh tools/list if stale), fix the reported fields and do not repeat the unchanged call. A returned PhxRE provider_timeout is a server/provider deadline: follow its remediation and reuse accessible partial Evidence. A host error such as 'timed out awaiting tools/call' without a PhxRE result is a client deadline, not proof that work or cleanup stopped. Do not repeat the unchanged analysis. Increase the host's tool deadline with execution/cleanup/delivery headroom; when configuration is not editable, report the required setting (Codex: mcp_servers.<server>.tool_timeout_sec, seconds). Server analysis_timeout_ms, when advertised, is a separate millisecond budget; raising it cannot fix a shorter client deadline. Session state does not establish completion of every target-free operation.";
const installSessionToolAvailability = (session, options, environment, fridaInstrumentation) => {
    if (session === undefined)
        return undefined;
    const linux = process.platform === "linux";
    const linuxX64 = linux && process.arch === "x64";
    const pwntools = linuxX64 && isAbsolute(environment.PHXRE_PWNTOOLS_PYTHON ?? "");
    const basePolicy = sessionAvailabilityPolicy(options.availabilityPolicy, {
        optionalProviderLoadFailures: options.optionalProviderLoadFailures,
        optionalFeatures: {
            packetCaptureEnabled: options.packetCapture !== undefined ||
                (linux && isAbsolute(environment.PHXRE_TSHARK_COMMAND ?? "")),
            signalRecordingEnabled: options.signalRecording !== undefined ||
                (linux && isAbsolute(environment.PHXRE_SIGROK_COMMAND ?? "")),
            wasmArtifactEnabled: options.wasmArtifact !== undefined ||
                isAbsolute(environment.PHXRE_WABT_BIN_DIRECTORY ?? ""),
            evmInterfaceEnabled: options.evmInterface !== undefined || linuxX64,
            webModuleResolutionEnabled: options.webModuleTrace !== undefined ||
                isAbsolute(environment.PHXRE_BROWSER_EXECUTABLE ?? ""),
            recordedCrashEnabled: options.recordedCrash !== undefined || pwntools,
            binaryLayoutEnabled: options.binaryLayout !== undefined || pwntools,
            firmwareInspectionEnabled: options.firmwareAnalysis !== undefined ||
                (linux && isAbsolute(environment.PHXRE_BINWALK_COMMAND ?? "")),
            firmwareExtractionEnabled: options.firmwareAnalysis !== undefined ||
                (linux && isAbsolute(environment.PHXRE_UNBLOB_COMMAND ?? "")),
            browserObservationEnabled: options.browserObservation !== undefined,
            javascriptRecoveryEnabled: options.javascriptRecovery !== undefined ||
                (linuxX64 && isAbsolute(environment.PHXRE_WAKARU_COMMAND ?? "")),
            browserScenarioEnabled: options.browserScenarioCapture !== undefined,
            electronObservationEnabled: options.electronObservation !== undefined,
            electronAutomationEnabled: options.electronActiveObservation !== undefined,
            v8InspectorObservationEnabled: options.javascriptRuntimeObservation !== undefined,
        },
    });
    const policy = () => {
        const value = basePolicy();
        const fridaFailure = options.optionalProviderLoadFailures?.fridaInstrumentation ??
            fridaInstrumentation.availabilityFailure?.();
        return fridaFailure === undefined
            ? value
            : {
                ...value,
                optionalProviderLoadFailures: {
                    ...value.optionalProviderLoadFailures,
                    fridaInstrumentation: fridaFailure,
                },
            };
    };
    return {
        policy,
        ...(options.evmInterface !== undefined || !linuxX64
            ? {}
            : {
                evmLimiterAvailability: (signal) => evmLimiterAvailability(environment, { signal }),
            }),
    };
};
const createMcpServer = (session, delivery, compactPresentation, omitOutputSchemas) => new EvidenceMcpServer({
    name: PRODUCT_IDENTITY.mcpServerKey,
    version: PRODUCT_IDENTITY.packageVersion,
}, {
    capabilities: {},
    instructions: `${session === undefined
        ? ACTIVE_TARGET_INSTRUCTIONS
        : TARGET_FREE_INSTRUCTIONS} ${RECOVERY_INSTRUCTIONS} ${UNTRUSTED_CONTENT_INSTRUCTIONS}`,
}, session === undefined
    ? undefined
    : (evidence) => session.recordEvidence(evidence), delivery, compactPresentation, omitOutputSchemas);
/**
 * Construct one MCP server without acquiring subprocess resources.
 * Supplying a session adds target lifecycle tools; omitting it retains the
 * fixed-target seam used by focused tests and embedders.
 */
export const createServer = (source, options = {}) => {
    const session = source.kind === "session" ? source.session : undefined;
    const analysis = source.kind === "session" ? source.session : source.analysis;
    const environment = snapshotEnvironment(options.environment ?? process.env);
    const omitOutputSchemas = outputSchemasOmitted(environment);
    const providerEnvironment = captureProviderEnvironment(options.providerEnvironment, environment);
    const delivery = selectToolResultDelivery(environment, options.delivery);
    const evmInterface = options.evmInterface ?? evmInterfaceModule.create(environment);
    const sqliteDatabase = options.sqliteDatabase ?? createSqliteDatabaseService(environment);
    const binaryLayout = options.binaryLayout ?? createBinaryLayoutService(environment);
    const recordedCrash = options.recordedCrash ?? createRecordedCrashService(environment);
    const webSourceLocation = options.webSourceLocation ?? createWebSourceLocationService(environment);
    const webModuleTrace = options.webModuleTrace ?? createWebModuleTraceService(environment);
    const desktopApplication = createDesktopApplicationService();
    const goBinary = options.goBinary ?? createGoBinaryService();
    const rustBinary = options.rustBinary ?? createRustBinaryService();
    const modelArtifact = createModelArtifactService();
    const gpuCodeObjects = createGpuCodeObjectsService();
    const il2cppMetadata = options.il2cppMetadata ?? createIl2cppMetadataService();
    const peResources = createPeResourcesService();
    const electronFuses = options.electronFuses ?? createElectronFuseService();
    const webNetworkCapture = options.webNetworkCapture ?? createWebNetworkCaptureService(environment);
    const javascriptRecovery = options.javascriptRecovery ?? createJavaScriptRecoveryProvider(environment);
    const artifactResources = new ArtifactResourceScope();
    const reverseEngineering = createReverseEngineeringService(providerEnvironment);
    const firmwareAnalysis = new FirmwareAnalysisService(options.firmwareAnalysis ?? createFirmwareAnalysisProvider(environment));
    const selectedOptions = {
        ...options,
        environment,
        delivery,
        evmInterface,
        sqliteDatabase,
        binaryLayout,
        recordedCrash,
        webSourceLocation,
        webModuleTrace,
        javascriptRecovery,
    };
    const startedAt = new Date().toISOString();
    const logger = options.logger ?? silentLogger;
    const server = createMcpServer(session, delivery, selectCompactInputSchemaPresentation(environment), omitOutputSchemas);
    const gdbSessions = new GdbSessionManager({
        environment: providerEnvironment,
    });
    const rizinDebugSessions = new RizinDebugSessionManager(providerEnvironment);
    const android = options.androidAnalysis ?? createAndroidAnalysisProvider(environment);
    const pcap = options.pcapAnalysis ?? createPcapAnalysisProvider(environment);
    const flutter = options.flutterAnalysis ?? createFlutterBuildAnalysisProvider();
    const fridaInstrumentation = options.fridaInstrumentation ?? new FridaInstrumentationManager();
    const wasmArtifact = wasmArtifactModule.create(environment, options.wasmArtifact);
    const packetCapture = options.packetCapture ?? createPacketCaptureService(environment);
    const signalRecording = options.signalRecording ?? createSignalRecordingService(environment);
    const webRuntime = options.webRuntime ?? createWebRuntimeService();
    const apktool = options.apktoolAnalysis ??
        createApktoolResourceAnalysisProvider(environment);
    const jeb = options.jebAnalysis ?? createJebAnalysisProvider(environment);
    const adbDevice = options.adbDeviceAnalysis ?? createAdbDeviceAnalysisProvider(environment);
    const cutter = new CutterBridgeService(new CutterBridgeClient(providerEnvironment));
    let providerClose;
    const closeProviders = () => {
        providerClose ??= Promise.allSettled([
            android.close(),
            cutter.close(),
            fridaInstrumentation.closeAll(),
            wasmArtifact.close(),
            packetCapture.close(),
            signalRecording.close(),
            apktool.close(),
            jeb.close(),
            adbDevice.close(),
            flutter.close(),
            pcap.close(),
            evmInterface.close(),
            sqliteDatabase.close(),
            binaryLayout.close(),
            recordedCrash.close(),
            webSourceLocation.close(),
            webModuleTrace.close(),
            desktopApplication.close(),
            goBinary.close(),
            rustBinary.close(),
            il2cppMetadata.close(),
            modelArtifact.close(),
            gpuCodeObjects.close(),
            peResources.close(),
            electronFuses.close(),
            webNetworkCapture.close(),
            javascriptRecovery.close?.() ?? Promise.resolve(),
            ...(options.optionalObservationProviderOwner === "caller"
                ? []
                : [
                    options.browserObservation?.close?.() ?? Promise.resolve(),
                    options.browserScenarioCapture?.close?.() ?? Promise.resolve(),
                    options.electronObservation?.close?.() ?? Promise.resolve(),
                    options.electronActiveObservation?.close?.() ?? Promise.resolve(),
                    options.javascriptRuntimeObservation?.close?.() ??
                        Promise.resolve(),
                ]),
            webRuntime.provider.close?.() ?? Promise.resolve(),
            artifactResources.close(),
            reverseEngineering.close(),
            firmwareAnalysis.close(),
            gdbSessions.closeAll(),
            rizinDebugSessions.closeAll(),
        ])
            .then((results) => {
            const failures = results.flatMap((result) => result.status === "rejected" ? [result.reason] : []);
            if (failures.length > 0)
                throw new AggregateError(failures, "PhxRE provider cleanup failed");
        })
            .catch((cause) => {
            providerClose = undefined;
            throw cause;
        });
        return providerClose;
    };
    const availability = installSessionToolAvailability(session, options, environment, fridaInstrumentation);
    const toolLogger = logger.child({ layer: "server" });
    const { evidenceById, activeTarget, recordEvidence, recordEvidenceWithUnknown, } = createSessionRecorders(server, session);
    const analysisAdmission = withAdmittedAnalysis(source);
    const toolContext = {
        server,
        session,
        options: selectedOptions,
        environment,
        logger: toolLogger,
        evidenceById,
        activeTarget,
        recordEvidence,
        recordEvidenceWithUnknown,
        withAdmittedAnalysis: analysisAdmission,
        artifactResources,
        goBinary,
        rustBinary,
        il2cppMetadata,
        peResources,
        electronFuses,
        webNetworkCapture,
    };
    registerDesktopApplicationTool(server, desktopApplication, toolLogger, recordEvidence, analysisAdmission, evidenceById);
    registerModelArtifactTools(server, modelArtifact, toolLogger, recordEvidence, analysisAdmission, evidenceById);
    registerGpuCodeObjectsTools(server, gpuCodeObjects, toolLogger, recordEvidence, analysisAdmission, evidenceById);
    registerBinaryAnalysisTools(toolContext);
    registerReverseEngineeringTools(server, reverseEngineering, toolLogger, delivery, session === undefined
        ? undefined
        : (evidence) => session.recordEvidence(evidence), analysisAdmission, session === undefined
        ? undefined
        : () => session.invalidateSnapshotForExternalMutation(), session === undefined
        ? undefined
        : (path, signal, operation, rebindFailure) => session.withAdmittedExternalMutation(path, signal, operation, rebindFailure), evidenceById);
    registerFridaTools(server, fridaInstrumentation, toolLogger, delivery, session === undefined
        ? undefined
        : (evidence) => session.recordEvidence(evidence), evidenceById);
    registerCutterTools(server, cutter, toolLogger, delivery, session === undefined
        ? undefined
        : (evidence) => session.recordEvidence(evidence), session);
    registerGdbTools(server, gdbSessions, toolLogger, delivery, session === undefined
        ? undefined
        : (evidence) => session.recordEvidence(evidence), session, evidenceById);
    registerRizinDebugTools(server, rizinDebugSessions, toolLogger, delivery, session === undefined
        ? undefined
        : (evidence) => session.recordEvidence(evidence), session);
    const previousOnclose = server.server.onclose;
    server.server.onclose = () => {
        previousOnclose?.();
        void closeProviders().catch((cause) => {
            logger.error({ error: cause instanceof Error ? cause.message : String(cause) }, "Provider cleanup failed during server shutdown");
        });
    };
    const closeServer = server.close.bind(server);
    server.close = async () => {
        const results = await Promise.allSettled([closeServer(), closeProviders()]);
        for (const result of results)
            if (result.status === "rejected")
                throw result.reason;
    };
    registerCaptureTools(server, packetCapture, toolLogger, recordEvidence, analysisAdmission);
    registerSignalTools(server, signalRecording, toolLogger, recordEvidence, analysisAdmission);
    registerConfiguredAnalysisTools(toolContext, android, wasmArtifact, evmInterface, jeb, firmwareAnalysis, webRuntime);
    registerAdbTools(server, new AdbDeviceAnalysisService(adbDevice), toolLogger, recordEvidence, analysisAdmission);
    registerPcapTools(server, new PcapAnalysisService(pcap), toolLogger, recordEvidence, analysisAdmission, evidenceById);
    registerFlutterTools(server, new FlutterBuildAnalysisService(flutter), toolLogger, recordEvidence, analysisAdmission, evidenceById);
    registerApktoolTools(server, new ApktoolResourceAnalysisService(apktool), toolLogger, recordEvidence, analysisAdmission);
    registerObservationTools(toolContext);
    registerGuidedPrompts(server, analysis, session);
    if (session !== undefined) {
        registerSessionTools(server, session, toolLogger, {
            ...selectedOptions,
            artifactResources,
            ...(availability === undefined
                ? {}
                : { availabilityPolicy: availability.policy }),
            ...(availability?.evmLimiterAvailability === undefined
                ? {}
                : { evmLimiterAvailability: availability.evmLimiterAvailability }),
            androidAnalysisAvailability: (signal) => android.inspectAvailability(signal),
            adbAnalysisAvailability: (signal) => adbDevice.inspectAvailability(signal),
            apktoolAnalysisAvailability: (signal) => apktool.inspectAvailability(signal),
            jebAnalysisAvailability: (signal) => jeb.inspectAvailability(signal),
            startedAt,
        });
    }
    return server;
};
const selectToolResultDelivery = (environment, selected) => {
    if (selected !== undefined)
        return selected;
    const configured = parseMcpResponseBudget(environment.PHXRE_MCP_MAX_RESPONSE_BYTES);
    if (!configured.ok)
        throw configured.error;
    return createToolResultDelivery(configured.value);
};
const outputSchemasOmitted = (environment) => {
    const configured = parseMcpOutputSchemaProfile(environment.PHXRE_MCP_OUTPUT_SCHEMA_PROFILE);
    if (!configured.ok)
        throw configured.error;
    return configured.value !== "full";
};
const selectCompactInputSchemaPresentation = (environment) => {
    const configured = parseMcpInputSchemaProfile(environment.PHXRE_MCP_INPUT_SCHEMA_PROFILE);
    if (!configured.ok)
        throw configured.error;
    return compactPresentationForMcpInputSchemaProfile(configured.value);
};
const registerConfiguredAnalysisTools = ({ server, options, environment, logger: toolLogger, evidenceById, recordEvidence, withAdmittedAnalysis, goBinary, rustBinary, il2cppMetadata, peResources, webNetworkCapture, artifactResources, }, android, wasmArtifact, evmInterface, jeb, firmwareAnalysis, webRuntime) => {
    registerAndroidTools(server, new AndroidAnalysisService(android), toolLogger, recordEvidence, withAdmittedAnalysis, evidenceById);
    registerJebTools(server, new JebAnalysisService(jeb), toolLogger, recordEvidence, withAdmittedAnalysis);
    registerBinaryDiagnosticsTools(server, options.binaryLayout ?? createBinaryLayoutService(environment), toolLogger, recordEvidence, evidenceById, withAdmittedAnalysis);
    registerAnalysisViewTool(server, toolLogger, evidenceById, recordEvidence, withAdmittedAnalysis, artifactResources);
    registerPeResourcesTool(server, peResources, toolLogger, recordEvidence, withAdmittedAnalysis);
    registerGoTools(server, goBinary, toolLogger, recordEvidence, withAdmittedAnalysis, evidenceById);
    registerIl2cppTools(server, il2cppMetadata, toolLogger, recordEvidence, withAdmittedAnalysis, evidenceById);
    registerRustTools(server, rustBinary, toolLogger, recordEvidence, withAdmittedAnalysis, evidenceById);
    registerWasmTools(server, wasmArtifact, toolLogger, recordEvidence, withAdmittedAnalysis, evidenceById);
    registerEvmTools(server, evmInterface, toolLogger, recordEvidence, withAdmittedAnalysis, evidenceById);
    registerSqliteTools(server, options.sqliteDatabase ?? createSqliteDatabaseService(environment), toolLogger, recordEvidence, withAdmittedAnalysis);
    registerRecordedCrashTools(server, options.recordedCrash ?? createRecordedCrashService(environment), toolLogger, recordEvidence, withAdmittedAnalysis);
    registerFirmwareTools(server, firmwareAnalysis, toolLogger, recordEvidence, withAdmittedAnalysis);
    registerWebModuleTool(server, options.webModuleTrace ?? createWebModuleTraceService(environment), toolLogger, recordEvidence, withAdmittedAnalysis);
    registerWebSourceLocationTool(server, options.webSourceLocation ?? createWebSourceLocationService(environment), toolLogger, recordEvidence, withAdmittedAnalysis);
    registerWebRuntimeTools(server, webRuntime, toolLogger, recordEvidence, withAdmittedAnalysis);
    registerWebNetworkCaptureTool(server, webNetworkCapture, toolLogger, recordEvidence, withAdmittedAnalysis, evidenceById);
    registerJavaScriptRecoveryTool(server, new JavaScriptRecoveryService(options.javascriptRecovery ??
        createJavaScriptRecoveryProvider(environment)), toolLogger, recordEvidence, withAdmittedAnalysis);
};
const createSessionRecorders = (server, session) => ({
    evidenceById: session === undefined
        ? undefined
        : (evidenceId) => session.evidenceForAnalysis?.(evidenceId) ??
            session.evidenceById(evidenceId),
    activeTarget: session === undefined ? undefined : () => session.activeTarget(),
    recordEvidence: session === undefined
        ? undefined
        : (evidence) => session.recordEvidence(evidence),
    recordEvidenceWithUnknown: session === undefined
        ? undefined
        : (evidence, input) => session.recordEvidenceWithUnknown(evidence, input),
});
const registerBinaryAnalysisTools = ({ server, session, logger, activeTarget, recordEvidence, recordEvidenceWithUnknown, evidenceById, withAdmittedAnalysis, }) => {
    const recordUnknown = session === undefined
        ? undefined
        : (input) => session.recordUnknown(input);
    const analysisOptions = {
        logger,
        activeTarget,
        recordEvidence,
        recordUnknown,
        evidenceById,
        withAdmittedAnalysis,
    };
    registerOfficialTools(server, analysisOptions);
    registerEnhancedTools(server, {
        ...analysisOptions,
        analysisProfile: session === undefined
            ? undefined
            : (operation) => session.analysisProfile() ?? session.analysisProfile(operation),
        allowsSnapshotReplay: session === undefined
            ? undefined
            : (operation) => session.allowsSnapshotReplay(operation),
        recordWorkflowSnapshot: session === undefined
            ? undefined
            : (input) => session.recordWorkflowSnapshot(input),
    });
    const evidenceOptions = {
        logger,
        activeTarget,
        recordEvidence,
        withAdmittedAnalysis,
    };
    registerNativeTools(server, { ...evidenceOptions, evidenceById });
    registerArtifactTools(server, { ...evidenceOptions, evidenceById });
    registerManagedTools(server, { ...evidenceOptions, evidenceById });
    if (session !== undefined)
        registerManagedWorkflowTools(server, {
            logger,
            recordEvidence,
            recordEvidenceWithUnknown,
            session,
            withAdmittedAnalysis,
        });
};
const registerObservationTools = ({ electronFuses, evidenceById, server, options, logger, recordEvidence, recordEvidenceWithUnknown, withAdmittedAnalysis, artifactResources, }) => {
    const common = { logger, recordEvidence, withAdmittedAnalysis };
    registerWebScriptTool(server, { ...common, artifactResources });
    registerBrowserTools(server, {
        ...common,
        browser: options.browserObservation,
        loadFailure: options.optionalProviderLoadFailures?.browserObservation,
    });
    registerBrowserScenarioTool(server, {
        ...common,
        provider: options.browserScenarioCapture,
        loadFailure: options.optionalProviderLoadFailures?.browserScenarioCapture,
    });
    registerElectronTools(server, {
        ...common,
        artifactResources,
        evidenceById,
        electron: options.electronObservation,
        electronActive: options.electronActiveObservation,
        electronFuses,
        observationLoadFailure: options.optionalProviderLoadFailures?.electronObservation,
        activeLoadFailure: options.optionalProviderLoadFailures?.electronActiveObservation,
    });
    registerJavaScriptRuntimeObservationTools(server, {
        ...common,
        runtime: options.javascriptRuntimeObservation,
        loadFailure: options.optionalProviderLoadFailures?.javascriptRuntimeObservation,
    });
    registerApplicationTools(server, {
        evidenceById,
        logger,
        recordEvidence,
        recordEvidenceWithUnknown,
        withAdmittedAnalysis,
    });
};
