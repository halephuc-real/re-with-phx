import { dirname } from "node:path";
import { constants } from "node:fs";
import { access, realpath, stat } from "node:fs/promises";
import { AnalysisCapabilityUnavailableError, AnalysisInputError, } from "../../domain/analysisErrorCore.js";
import { err, ok } from "../../domain/result.js";
import { createElectronActiveEvidence } from "./ElectronActiveEvidence.js";
const OPERATION = "capture_electron_scenario";
const PROVIDER_ID = "phxre-playwright-electron-active";
const resolveInputPath = async (field, selected) => {
    try {
        return ok(await realpath(selected));
    }
    catch (cause) {
        return err({
            issue: {
                path: [field],
                reason: "invalid_value",
                message: `Cannot resolve ${field} ${selected}: ${cause instanceof Error ? cause.message : String(cause)}`,
            },
            cause,
        });
    }
};
/** Resolve the executable and require a launchable regular file before any spawn. */
const resolveExecutablePath = async (selected) => {
    const resolved = await resolveInputPath("executable_path", selected);
    if (!resolved.ok)
        return resolved;
    try {
        if (!(await stat(resolved.value)).isFile())
            throw new Error("not a regular file");
        if (process.platform !== "win32")
            await access(resolved.value, constants.X_OK);
        return resolved;
    }
    catch (cause) {
        return err({
            issue: {
                path: ["executable_path"],
                reason: "invalid_value",
                message: `executable_path ${selected} is not an executable file: ${cause instanceof Error ? cause.message : String(cause)}`,
            },
            cause,
        });
    }
};
const canonicalizeInput = async (input) => {
    const [executable, application, root] = await Promise.all([
        resolveExecutablePath(input.executable_path),
        resolveInputPath("application_path", input.application_path),
        input.application_root === undefined
            ? Promise.resolve(ok(undefined))
            : resolveInputPath("application_root", input.application_root),
    ]);
    if (!executable.ok || !application.ok || !root.ok) {
        const failures = [executable, application, root].flatMap((result) => result.ok ? [] : [result.error]);
        return err(new AnalysisInputError(OPERATION, {
            cause: new AggregateError(failures.map(({ cause }) => cause), "Electron paths could not be resolved"),
        }, failures.map(({ issue }) => issue)));
    }
    return ok({
        ...input,
        executable_path: executable.value,
        application_path: application.value,
        application_root: root.value ?? dirname(application.value),
    });
};
/** Canonicalize request paths and execute one provider-owned Electron run. */
export const captureElectronScenario = async (provider, input, options = {}) => {
    const canonical = await canonicalizeInput(input);
    if (!canonical.ok)
        return canonical;
    if (provider === undefined)
        return err(new AnalysisCapabilityUnavailableError(PROVIDER_ID, OPERATION, "active Electron observation provider is not configured"));
    const captured = await provider.capture(canonical.value, options);
    return captured.ok
        ? {
            ok: true,
            value: createElectronActiveEvidence(canonical.value, captured.value, provider.identity()),
        }
        : captured;
};
