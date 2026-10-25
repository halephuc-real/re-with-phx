import { registerCoreBinaryCommands } from "./coreBinaryCommands.js";
import { registerCoreNativeCommands } from "./coreNativeCommands.js";
/** Register core binary and native deep-analysis CLI commands. */
export const registerCoreAnalysisCommands = (cli, logger, runDirectAnalysis) => {
    registerCoreBinaryCommands(cli, logger, runDirectAnalysis);
    registerCoreNativeCommands(cli, logger, runDirectAnalysis);
};
