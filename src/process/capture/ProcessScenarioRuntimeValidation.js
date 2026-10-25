import { constants as fsConstants } from "node:fs";
import { access, realpath, stat } from "node:fs/promises";
import { delimiter, isAbsolute, join, resolve, sep } from "node:path";
import { AnalysisInputError } from "../../domain/analysisErrorCore.js";
import { snapshotEnvironment } from "../snapshotEnvironment.js";
import { processCaptureCancelled } from "./ProcessCaptureError.js";
/** Resolve caller-selected executable and observation paths for this execution. */
export const resolveProcessScenarioRuntimePaths = async (scenario, environment = process.env, platform = process.platform) => {
    const selectedWorkingDirectory = resolve(scenario.working_directory);
    let workingDirectory;
    try {
        workingDirectory = await realpath(selectedWorkingDirectory);
    }
    catch (cause) {
        throw invalidScenarioPath("working_directory", `working directory could not be resolved: ${selectedWorkingDirectory}${osFailure(cause)}`, cause);
    }
    let workingDirectoryStat;
    try {
        workingDirectoryStat = await stat(workingDirectory);
    }
    catch (cause) {
        throw invalidScenarioPath("working_directory", `working directory could not be inspected: ${workingDirectory}${osFailure(cause)}`, cause);
    }
    if (!workingDirectoryStat.isDirectory())
        throw invalidScenarioPath("working_directory", `working directory is not a directory: ${workingDirectory}`);
    const executable = await resolveExecutable(scenario.executable, workingDirectory, snapshotEnvironment(scenario.environment, platform).PATH ??
        snapshotEnvironment(environment, platform).PATH ??
        "");
    const observationPaths = scenario.filesystem_observation_paths.map((path) => resolve(workingDirectory, path));
    return {
        ...scenario,
        executable,
        working_directory: workingDirectory,
        filesystem_observation_paths: observationPaths,
    };
};
/** Resolve a selected executable through the caller's effective PATH. */
export const resolveExecutable = async (command, workingDirectory, searchPath) => {
    const directories = searchPath
        .split(delimiter)
        .map((directory) => directory === ""
        ? workingDirectory
        : resolve(workingDirectory, directory));
    const candidates = isAbsolute(command) ||
        command.includes("/") ||
        (sep === "\\" && command.includes("\\"))
        ? [resolve(workingDirectory, command)]
        : directories.map((directory) => join(directory, command));
    const failures = [];
    for (const candidate of candidates) {
        try {
            await access(candidate, fsConstants.X_OK);
            if ((await stat(candidate)).isFile())
                return candidate;
            failures.push(`${candidate} (not a regular file)`);
        }
        catch (cause) {
            failures.push(`${candidate}${osFailure(cause)}`);
            continue;
        }
    }
    throw invalidScenarioPath("executable", `executable could not be resolved: ${command}; checked ${failures.join("; ")}`);
};
const invalidScenarioPath = (field, message, cause) => new AnalysisInputError("capture_process_scenario", cause === undefined ? undefined : { cause }, [{ path: [field], reason: "invalid_value", message }]);
const osErrorCode = (cause) => typeof cause === "object" &&
    cause !== null &&
    "code" in cause &&
    typeof cause.code === "string"
    ? cause.code
    : undefined;
const osFailure = (cause) => {
    const code = osErrorCode(cause);
    return code === undefined ? "" : ` (${code})`;
};
/** Reject cancellation before a process capture operation begins. */
export const assertNotCancelled = (signal) => {
    if (signal?.aborted === true)
        throw processCaptureCancelled(signal.reason);
};
