import pino from "pino";
import { z } from "zod";
import { ConfigurationError } from "./domain/configurationErrors.js";
import { err, ok } from "./domain/result.js";
/**
 * Settings the executable rejects before a command starts. MCP startup rejects
 * the same values. Doctor requires them in every readiness scope.
 */
export const PROCESS_START_CONFIGURATION_SETTINGS = ["PHXRE_LOG_LEVEL"];
/** True when `setting` prevents the PhxRE process from starting. */
export const blocksProcessStart = (setting) => PROCESS_START_CONFIGURATION_SETTINGS.some((candidate) => candidate === setting);
const logLevelSchema = z
    .enum(["trace", "debug", "info", "warn", "error", "fatal", "silent"])
    .default("info");
/** Parse the optional PHXRE_LOG_LEVEL environment variable. */
export const parseLogLevel = (value) => {
    const parsed = logLevelSchema.safeParse(value);
    if (parsed.success)
        return ok(parsed.data);
    return err(new ConfigurationError("Invalid PhxRE environment configuration", {
        cause: parsed.error,
        settings: parsed.error.issues.map(({ message }) => ({
            setting: "PHXRE_LOG_LEVEL",
            constraint: message,
        })),
    }));
};
/** Create a JSON logger on stderr so protocol and CLI result stdout stay valid. */
export const createLogger = (mode, level) => pino({
    level,
    base: { application: "phxre", mode },
}, pino.destination({ dest: 2, sync: false }));
/** Logger used by embedders that have not opted into process output. */
export const silentLogger = pino({ level: "silent" });
