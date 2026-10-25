import { z } from "incur";
import { executableFormatHintSchema, } from "../domain/dosCom.js";
import { binaryArchitectureSchema, rawBinaryEntryPointSchema, } from "../domain/rawBinary.js";
import { analysisProviderSelectorSchema } from "../contracts/providerSelection.js";
/** Parse decimal integer tokens before Number coercion can erase their syntax. */
export const cliIntegerArgument = (min) => z
    .string()
    .regex(/^[0-9]+$/u, "Expected a decimal integer")
    .pipe(z.coerce.number().safe().min(min));
export const providerSelectionOption = analysisProviderSelectorSchema
    .optional()
    .describe("Bind deep analysis to a provider ID or use deterministic auto selection");
/** Explicit interpretation for headerless native executable formats. */
export const formatSelectionOption = executableFormatHintSchema
    .optional()
    .describe("Explicit headerless interpretation (dos-com or raw-binary); omission preserves header-based detection");
export const architectureSelectionOption = binaryArchitectureSchema
    .optional()
    .describe("Caller-supplied CPU family; required with --target-format raw-binary");
export const entryPointSelectionOption = rawBinaryEntryPointSchema
    .optional()
    .describe("Caller-supplied load and entry address (0xhex); required with --target-format raw-binary");
/** Shared CLI flags that bind a native target interpretation. */
export const nativeOpenOptionFields = {
    "target-format": formatSelectionOption,
    architecture: architectureSelectionOption,
    "entry-point": entryPointSelectionOption,
    provider: providerSelectionOption,
};
export const directAnalysisOptions = (logger, snapshotPath, providerId, formatHint, architecture, entryPoint) => ({
    logger,
    snapshotPath,
    ...(formatHint === undefined ? {} : { formatHint }),
    ...(architecture === undefined ? {} : { architecture }),
    ...(entryPoint === undefined ? {} : { entryPoint }),
    ...(providerId === undefined ? {} : { providerId }),
});
/** Map native CLI flags onto the shared one-shot analysis options. */
export const directAnalysisOptionsFromCli = (logger, options) => directAnalysisOptions(logger, options.snapshot, options.provider, options["target-format"], options.architecture, options["entry-point"]);
