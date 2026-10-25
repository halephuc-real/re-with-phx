import { z } from "zod";
import { parseEnvironment, parseEnvironmentValues, } from "../config/environment.js";
import { ConfigurationError } from "../domain/configurationErrors.js";
import { err, ok } from "../domain/result.js";
import { effectiveClientServer, } from "./ClientConfigurationDocument.js";
import { PRODUCT_IDENTITY } from "../identity.js";
import { compareUnicodeCodePoints } from "../domain/unicodeCodePointOrder.js";
import { mergeEnvironmentOverrides, snapshotEnvironment, } from "../process/snapshotEnvironment.js";
import { dshDocument } from "./DshCordisPatch.js";
/** Read explicit PhxRE overrides without dropping peers when one value is invalid. */
export const clientRegistrationEnvironment = (parsed, overrides = {}, validation = "effective", platform = process.platform) => {
    if (parsed?.dialect === "dsh")
        return dshDocument(parsed.document).environment(overrides, validation, platform);
    const details = clientRegistrationEnvironmentDetails(parsed, overrides, validation, platform);
    return details.ok ? ok(details.value.values) : details;
};
/** Retain original strings and the parser-owned timeout facts. */
export const clientRegistrationEnvironmentDetails = (parsed, overrides = {}, validation = "effective", platform = process.platform) => {
    if (parsed?.dialect === "dsh") {
        const environment = dshDocument(parsed.document).environment(overrides, validation, platform);
        if (!environment.ok)
            return environment;
        return validatedDetails(environment.value, validation, platform);
    }
    const key = parsed?.dialect === "opencode" || parsed?.dialect === "opencode_v2"
        ? "environment"
        : "env";
    const registration = parsed === undefined
        ? undefined
        : effectiveClientServer(parsed, PRODUCT_IDENTITY.mcpServerKey);
    const raw = typeof registration === "object" && registration !== null
        ? Reflect.get(registration, key)
        : undefined;
    const existing = z
        .record(z.string(), z.string())
        .safeParse(raw === undefined ? {} : raw);
    if (!existing.success)
        return err(new ConfigurationError("Invalid PhxRE server environment", {
            settings: existing.error.issues.map((issue) => ({
                setting: [key, ...issue.path].join("."),
                constraint: "Server environment must be an object containing only string values",
            })),
        }));
    // Validate known settings with the runtime's parser, but retain the original
    // string overrides, including unknown client-specific keys and no defaults.
    const environment = mergeEnvironmentOverrides(existing.data, overrides, platform);
    return validatedDetails(environment, validation, platform);
};
/** Resolve the async provider-specific budget through its retained reader owner. */
export const clientRegistrationEnvironmentDetailsWithBudget = async (parsed, overrides, validation, resolveProviderRequestBudget, platform = process.platform) => {
    const details = clientRegistrationEnvironmentDetails(parsed, overrides, validation, platform);
    if (!details.ok || resolveProviderRequestBudget === undefined)
        return details;
    return validatedBudget(details.value, resolveProviderRequestBudget, platform);
};
const validatedDetails = (environment, validation, platform = process.platform) => {
    const runtimeEnvironment = snapshotEnvironment(environment, platform);
    const validated = validation === "fragment"
        ? parseEnvironmentValues(runtimeEnvironment)
        : parseEnvironment(runtimeEnvironment);
    if (!validated.ok)
        return validated;
    return ok({
        values: Object.fromEntries(Object.entries(environment).sort(([left], [right]) => compareUnicodeCodePoints(left, right))),
        timeoutInputs: {
            analysisProvider: validated.value.PHXRE_ANALYSIS_PROVIDER,
            ghidraStartupTimeoutMs: validated.value.PHXRE_GHIDRA_STARTUP_TIMEOUT_MS,
            hopperStartupTimeoutMs: validated.value.PHXRE_HOPPER_STARTUP_TIMEOUT_MS,
            ...(validated.value.PHXRE_JEB_MCP_TIMEOUT_MS === undefined
                ? {}
                : { jebMcpTimeoutMs: validated.value.PHXRE_JEB_MCP_TIMEOUT_MS }),
        },
    });
};
const validatedBudget = async (details, resolveProviderRequestBudget, platform) => {
    const providerBudget = await resolveProviderRequestBudget(details.timeoutInputs.analysisProvider, snapshotEnvironment(details.values, platform));
    if (!providerBudget.ok)
        return providerBudget;
    return ok({
        ...details,
        timeoutInputs: {
            ...details.timeoutInputs,
            ...(providerBudget.value === undefined
                ? {}
                : { providerRequestTimeoutMs: providerBudget.value }),
        },
    });
};
