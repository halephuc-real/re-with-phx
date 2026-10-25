import type { DoctorProviderInspection } from "./Doctor.js";
import { compareUnicodeCodePoints } from "../domain/unicodeCodePointOrder.js";

const SELECTED_REGISTRATION_SETTINGS = [
  "PHXRE_ANALYSIS_PROVIDER",
  "PHXRE_ASAR_MAX_HEADER_BYTES",
  "PHXRE_BRIDGE_MAX_REQUEST_BYTES",
  "PHXRE_CAPTURE_DECODER_OLD_GENERATION_MIB",
  "PHXRE_GHIDRA_DECOMPILE_TIMEOUT_SECONDS",
  "PHXRE_GHIDRA_STARTUP_TIMEOUT_MS",
  "PHXRE_HOPPER_STARTUP_TIMEOUT_MS",
  "PHXRE_JEB_MCP_TIMEOUT_MS",
  "PHXRE_MCP_INPUT_SCHEMA_PROFILE",
  "PHXRE_REGEX_MATCHING_DEADLINE_MS",
  "PHXRE_REGEX_WORKER_HEAP_REQUEST_MIB",
  "PHXRE_MCP_INITIALIZE_BUDGET_MS",
  "PHXRE_MCP_TOOLS_LIST_BUDGET_MS",
  "PHXRE_MCP_FIRST_CATALOG_BUDGET_MS",
  "PHXRE_MCP_DOCTOR_DEADLINE_MS",
] as const;

/** Preserve selected setup settings without copying unrelated process values. */
export const explicitSetupRegistrationEnvironment = (
  environment: Readonly<Record<string, string | undefined>>,
): Readonly<Record<string, string>> =>
  Object.fromEntries(
    SELECTED_REGISTRATION_SETTINGS.flatMap((key) => {
      const value = environment[key];
      return value === undefined ? [] : [[key, value]];
    }),
  );

/** Preserve adapter-published settings independently of runtime readiness. */
export const providerRegistrationEnvironment = (
  inspections: readonly DoctorProviderInspection[],
): Readonly<Record<string, string>> =>
  Object.fromEntries(
    inspections
      .flatMap(({ registrationEnvironment }) =>
        Object.entries(registrationEnvironment),
      )
      .sort(([left], [right]) => compareUnicodeCodePoints(left, right)),
  );
