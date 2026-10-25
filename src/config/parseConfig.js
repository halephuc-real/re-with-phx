import { accessSync, constants, statSync } from "node:fs";
import { ok } from "../domain/result.js";
import { parseEnvironment } from "./environment.js";
import { homeDirectoryFromEnvironment } from "./homeDirectory.js";
import { linuxHopperLauncherCandidates, PHXRE_MANAGED_LINUX_HOPPER_LAUNCHER, } from "../application/LinuxHopper.js";
import { MAC_HOPPER_SYSTEM_LAUNCHER, macHopperLauncherCandidates, } from "../application/MacHopperPaths.js";
const executableAvailable = (path) => {
    try {
        accessSync(path, constants.X_OK);
        return statSync(path).isFile();
    }
    catch {
        return false;
    }
};
export const defaultHopperLauncherPath = (platform, homeDirectory, executable = executableAvailable) => {
    if (platform === "darwin") {
        for (const candidate of macHopperLauncherCandidates(homeDirectory))
            if (executable(candidate))
                return candidate;
        return MAC_HOPPER_SYSTEM_LAUNCHER;
    }
    if (platform !== "linux")
        return MAC_HOPPER_SYSTEM_LAUNCHER;
    return (linuxHopperLauncherCandidates(homeDirectory).find(executable) ??
        PHXRE_MANAGED_LINUX_HOPPER_LAUNCHER);
};
/**
 * Environment native analysis admits. JEB validates its own timeout during
 * optional provider composition; that setting must not block unrelated
 * CLI/MCP startup. Registration validation still checks it directly.
 */
const nativeAnalysisEnvironment = (environment) => {
    const { PHXRE_JEB_MCP_TIMEOUT_MS: _jebTimeout, ...appEnvironment } = environment;
    return appEnvironment;
};
/**
 * The configuration error native commands return, without probing launchers.
 * Doctor uses this so readiness and analysis admit the same settings.
 */
export const nativeAnalysisConfigurationError = (environment) => {
    const parsed = parseEnvironment(nativeAnalysisEnvironment(environment));
    return parsed.ok ? undefined : parsed.error;
};
/** Parse provider configuration and runtime prerequisites at the composition root. */
export const parseConfig = (environment) => {
    const parsed = parseEnvironment(nativeAnalysisEnvironment(environment));
    if (!parsed.ok)
        return parsed;
    const env = parsed.value;
    return ok({
        ...(env.PHXRE_MCP_MAX_RESPONSE_BYTES === undefined
            ? {}
            : { mcpMaxResponseBytes: env.PHXRE_MCP_MAX_RESPONSE_BYTES }),
        ...(env.PHXRE_MCP_INPUT_SCHEMA_PROFILE === undefined
            ? {}
            : { mcpInputSchemaProfile: env.PHXRE_MCP_INPUT_SCHEMA_PROFILE }),
        analysisProvider: env.PHXRE_ANALYSIS_PROVIDER,
        ...(env.PHXRE_IDA_MCP_CONFIG === undefined
            ? {}
            : { idaMcpConfigPath: env.PHXRE_IDA_MCP_CONFIG }),
        ghidraInstallDir: env.GHIDRA_INSTALL_DIR,
        ghidraJavaHome: env.JAVA_HOME,
        ghidraStartupTimeoutMs: env.PHXRE_GHIDRA_STARTUP_TIMEOUT_MS,
        ...(env.PHXRE_GHIDRA_LANGUAGE_ID === undefined
            ? {}
            : {
                ghidraLanguageOverride: {
                    languageId: env.PHXRE_GHIDRA_LANGUAGE_ID,
                    ...(env.PHXRE_GHIDRA_COMPILER_SPEC_ID === undefined
                        ? {}
                        : { compilerSpecId: env.PHXRE_GHIDRA_COMPILER_SPEC_ID }),
                },
            }),
        ...(env.PHXRE_GHIDRA_SEED_FILE === undefined
            ? {}
            : { ghidraSeedFile: env.PHXRE_GHIDRA_SEED_FILE }),
        ...(env.PHXRE_GHIDRA_DISABLED_ANALYZERS === undefined
            ? {}
            : { ghidraDisabledAnalyzers: env.PHXRE_GHIDRA_DISABLED_ANALYZERS }),
        ...(env.PHXRE_GHIDRA_NATIVEAOT_JAR === undefined
            ? {}
            : { ghidraNativeAotJar: env.PHXRE_GHIDRA_NATIVEAOT_JAR }),
        ilspyCmdPath: env.PHXRE_ILSPY_CMD_PATH,
        hopperLauncherPath: env.HOPPER_LAUNCHER_PATH ??
            defaultHopperLauncherPath(process.platform, homeDirectoryFromEnvironment(environment, process.platform)),
        hopperStartupTimeoutMs: env.PHXRE_HOPPER_STARTUP_TIMEOUT_MS,
        hopperTargetPath: env.HOPPER_TARGET_PATH,
        hopperTargetKind: env.HOPPER_TARGET_KIND,
        hopperLoaderArgs: env.loaderArgs,
        logLevel: env.PHXRE_LOG_LEVEL,
        referenceSourcePolicy: {
            secretPatterns: env.referenceSecretPatterns,
        },
    });
};
