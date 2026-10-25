import { z } from "zod";
import { isAbsolute } from "node:path";
import { ConfigurationError } from "../domain/configurationErrors.js";
import { err, ok } from "../domain/result.js";
import { analysisProviderSelectorSchema } from "../contracts/providerSelection.js";
import { ghidraCompilerSpecIdSchema, ghidraLanguageIdSchema, } from "./ghidraLanguageOverride.js";
import { ghidraDisabledAnalyzersSchema } from "./ghidraDisabledAnalyzers.js";
import { DEFAULT_GHIDRA_STARTUP_TIMEOUT_MS, DEFAULT_HOPPER_STARTUP_TIMEOUT_MS, DEFAULT_SWIFTC_COMPILE_TIMEOUT_MS, providerStartupTimeoutSchema, } from "./providerStartupTimeout.js";
import { mcpInputSchemaProfileSchema } from "./mcpInputSchemaProfile.js";
import { mcpOutputSchemaProfileSchema } from "./mcpOutputSchemaProfile.js";
import { mcpResponseBudgetSchema } from "./mcpResponseBudget.js";
import { parseLoaderArgs, parseStringArray } from "./parsers.js";
const environmentSchema = z.object({
    PHXRE_ANALYSIS_PROVIDER: analysisProviderSelectorSchema.default("auto"),
    PHXRE_MCP_MAX_RESPONSE_BYTES: mcpResponseBudgetSchema.optional(),
    PHXRE_MCP_INPUT_SCHEMA_PROFILE: mcpInputSchemaProfileSchema.optional(),
    PHXRE_MCP_OUTPUT_SCHEMA_PROFILE: mcpOutputSchemaProfileSchema.optional(),
    PHXRE_IDA_MCP_CONFIG: z
        .string()
        .min(1)
        .refine(isAbsolute, "PHXRE_IDA_MCP_CONFIG must be absolute")
        .optional(),
    PHXRE_JEB_MCP_TIMEOUT_MS: providerStartupTimeoutSchema.optional(),
    GHIDRA_INSTALL_DIR: z
        .string()
        .min(1)
        .refine(isAbsolute, "GHIDRA_INSTALL_DIR must be absolute")
        .optional(),
    JAVA_HOME: z
        .string()
        .min(1)
        .refine(isAbsolute, "JAVA_HOME must be absolute")
        .optional(),
    PHXRE_GHIDRA_NATIVEAOT_JAR: z
        .string()
        .min(1)
        .refine(isAbsolute, "PHXRE_GHIDRA_NATIVEAOT_JAR must be absolute")
        .optional(),
    PHXRE_GHIDRA_STARTUP_TIMEOUT_MS: providerStartupTimeoutSchema.default(DEFAULT_GHIDRA_STARTUP_TIMEOUT_MS),
    PHXRE_HOPPER_STARTUP_TIMEOUT_MS: providerStartupTimeoutSchema.default(DEFAULT_HOPPER_STARTUP_TIMEOUT_MS),
    PHXRE_SWIFTC_COMPILE_TIMEOUT_MS: providerStartupTimeoutSchema.default(DEFAULT_SWIFTC_COMPILE_TIMEOUT_MS),
    PHXRE_GHIDRA_LANGUAGE_ID: ghidraLanguageIdSchema.optional(),
    PHXRE_GHIDRA_COMPILER_SPEC_ID: ghidraCompilerSpecIdSchema.optional(),
    PHXRE_GHIDRA_DISABLED_ANALYZERS: ghidraDisabledAnalyzersSchema.optional(),
    PHXRE_GHIDRA_SEED_FILE: z
        .string()
        .min(1)
        .refine(isAbsolute, "PHXRE_GHIDRA_SEED_FILE must be absolute")
        .optional(),
    PHXRE_ILSPY_CMD_PATH: z
        .string()
        .min(1)
        .refine(isAbsolute, "PHXRE_ILSPY_CMD_PATH must be absolute")
        .optional(),
    HOPPER_LAUNCHER_PATH: z.string().min(1).optional(),
    HOPPER_TARGET_PATH: z.string().min(1).optional(),
    HOPPER_TARGET_KIND: z.enum(["executable", "database"]).default("executable"),
    HOPPER_LOADER_ARGS_JSON: z.string().optional(),
    PHXRE_LOG_LEVEL: z
        .enum(["trace", "debug", "info", "warn", "error", "fatal", "silent"])
        .default("info"),
    PHXRE_REFERENCE_SECRET_PATTERNS_JSON: z.string().default("[]"),
});
/** Parse the JEB-only timeout at its isolated provider-composition boundary. */
export const parseJebMcpTimeoutMs = (value) => {
    if (value === undefined)
        return ok(undefined);
    const parsed = providerStartupTimeoutSchema.safeParse(value);
    if (parsed.success)
        return ok(parsed.data);
    return err(new ConfigurationError("Invalid PhxRE environment configuration", {
        cause: parsed.error,
        settings: [
            {
                setting: "PHXRE_JEB_MCP_TIMEOUT_MS",
                constraint: parsed.error.issues[0]?.message ?? "must be a valid timeout",
            },
        ],
    }));
};
/** Parse individual settings before layered registration fragments are merged. */
export const parseEnvironmentValues = (environment, unresolvedSettings = new Set()) => {
    // Unknown client-specific entries are preserved by registration owners and
    // still cross the child-process boundary. Check their byte admission before
    // the known-setting schema strips them; never include rejected values.
    // Cordis expression values stay unknown, but their literal names are known.
    const keys = new Set([...Object.keys(environment), ...unresolvedSettings]);
    const invalidEntries = [...keys]
        .filter((key) => key.includes("\0") ||
        (Object.hasOwn(environment, key) && environment[key]?.includes("\0")))
        .map((setting) => ({
        setting,
        constraint: "Environment variable names and values must not contain NUL bytes",
    }));
    if (invalidEntries.length > 0)
        return err(new ConfigurationError("Invalid PhxRE environment configuration", {
            settings: invalidEntries,
        }));
    const parsed = environmentSchema.safeParse(environment);
    if (!parsed.success) {
        // Zod messages name the constraint, never the rejected value.
        const settings = parsed.error.issues.map((issue) => ({
            setting: String(issue.path[0] ?? "environment"),
            constraint: issue.message,
        }));
        return err(new ConfigurationError("Invalid PhxRE environment configuration", {
            cause: parsed.error,
            settings,
        }));
    }
    const { HOPPER_LOADER_ARGS_JSON: encodedLoaderArgs, PHXRE_REFERENCE_SECRET_PATTERNS_JSON: encodedSecretPatterns, ...env } = parsed.data;
    const loaderArgs = parseLoaderArgs(encodedLoaderArgs);
    if (!loaderArgs.ok)
        return loaderArgs;
    const secretPatterns = parseStringArray(encodedSecretPatterns, "PHXRE_REFERENCE_SECRET_PATTERNS_JSON");
    if (!secretPatterns.ok)
        return secretPatterns;
    return ok({
        ...env,
        loaderArgs: loaderArgs.value,
        referenceSecretPatterns: secretPatterns.value,
    });
};
/** Validate complete runtime semantics without probing the host or persisting defaults. */
export const parseEnvironment = (environment, 
// Registration expressions are not evaluated; their absence is not proven.
unresolvedSettings = new Set()) => {
    const parsed = parseEnvironmentValues(environment, unresolvedSettings);
    if (!parsed.ok)
        return parsed;
    const env = parsed.value;
    // Ghidra's analyzeHeadless accepts -cspec only together with -processor.
    if (env.PHXRE_GHIDRA_COMPILER_SPEC_ID !== undefined &&
        env.PHXRE_GHIDRA_LANGUAGE_ID === undefined &&
        !unresolvedSettings.has("PHXRE_GHIDRA_LANGUAGE_ID"))
        return err(new ConfigurationError("Invalid PhxRE environment configuration", {
            settings: [
                {
                    setting: "PHXRE_GHIDRA_COMPILER_SPEC_ID",
                    constraint: "requires PHXRE_GHIDRA_LANGUAGE_ID",
                },
            ],
        }));
    return parsed;
};
