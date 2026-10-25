import { compareUnicodeCodePoints } from "../domain/unicodeCodePointOrder.js";
const SELECTED_REGISTRATION_SETTINGS = [
    "PHXRE_ANALYSIS_PROVIDER",
    "PHXRE_GHIDRA_STARTUP_TIMEOUT_MS",
    "PHXRE_HOPPER_STARTUP_TIMEOUT_MS",
    "PHXRE_JEB_MCP_TIMEOUT_MS",
    "PHXRE_MCP_INPUT_SCHEMA_PROFILE",
];
/** Preserve selected setup settings without copying unrelated process values. */
export const explicitSetupRegistrationEnvironment = (environment) => Object.fromEntries(SELECTED_REGISTRATION_SETTINGS.flatMap((key) => {
    const value = environment[key];
    return value === undefined ? [] : [[key, value]];
}));
/** Preserve adapter-published settings independently of runtime readiness. */
export const providerRegistrationEnvironment = (inspections) => Object.fromEntries(inspections
    .flatMap(({ registrationEnvironment }) => Object.entries(registrationEnvironment))
    .sort(([left], [right]) => compareUnicodeCodePoints(left, right)));
