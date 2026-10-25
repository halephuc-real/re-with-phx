import { artifactFileCancellationCause } from "../artifacts/ArtifactFileOperation.js";
import { signalDecodersSchema, } from "../domain/signals/signalDecoders.js";
import { DecoderDiscoveryBudgetError, parseDecoderDiscovery, } from "./parseDecoderDiscovery.js";
import { parseSigrokSelectorRejection, } from "./sigrokSelectorRejection.js";
import { BOUNDED_PRODUCER_LIMITS as LIMITS, prlimitArgumentVector, readLinuxResourceLimits, } from "../process/LinuxResourceLimits.js";
import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { access, realpath, writeFile } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { createAnalysisExecution, } from "../application/AnalysisProvider.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { ArtifactAnalysisResources, } from "../process/ArtifactAnalysisResources.js";
import { readStableArtifact } from "../artifacts/readStableArtifact.js";
import { AnalysisError, } from "../domain/analysisErrorBase.js";
import { AnalysisAccessDeniedError, AnalysisArtifactChangedError, AnalysisCancelledError, AnalysisCapabilityUnavailableError, AnalysisInputError, AnalysisOutputError, AnalysisResourceConstraintError, } from "../domain/analysisErrorCore.js";
import { createEvidence } from "../domain/evidence.js";
import { fixedAllowanceOptions } from "../domain/fixedAllowanceRemediation.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { windowAnnotationText } from "../domain/signals/annotationTextWindow.js";
import { signalRecordingSchema, } from "../domain/signals/signalRecording.js";
import { err, ok } from "../domain/result.js";
import { runOwnedCommand, OwnedCommandFailure, } from "../process/OwnedCommand.js";
import { PrivateRuntimeRoot } from "../process/PrivateRuntimeRoot.js";
const OPERATION = "decode_signal_recording";
export const SIGROK_PROVIDER_IDENTITY = {
    id: "sigrok-recording",
    name: "PhxRE sigrok recording adapter",
    version: "sigrok-cli@0.7.2",
};
/** Decode selected recordings only, retaining cleanup ownership across failures. */
export class SigrokRecordingProvider {
    environment;
    launcher;
    createRuntime;
    platform;
    readArtifact;
    readLimits;
    #resources;
    constructor(environment = process.env, launcher, createRuntime = () => PrivateRuntimeRoot.create({ prefix: "phxre-sigrok-" }), platform = process.platform, readArtifact = readStableArtifact, readLimits = readLinuxResourceLimits) {
        this.environment = environment;
        this.launcher = launcher;
        this.createRuntime = createRuntime;
        this.platform = platform;
        this.readArtifact = readArtifact;
        this.readLimits = readLimits;
        this.#resources = new ArtifactAnalysisResources(SIGROK_PROVIDER_IDENTITY.id, OPERATION, readArtifact, readLimits, {
            message: "A sigrok operation is already active; retry after it completes.",
            details: { max_concurrent_decodes: 1 },
        });
    }
    decode(input, options) {
        return this.#resources.run(() => this.#executeRequest(input, options), options?.signal);
    }
    inspectDecoders(input, options) {
        return this.#resources.run(() => this.#executeRequest(input, options), options?.signal, "inspect_signal_decoders");
    }
    close() {
        return this.#resources.close();
    }
    async #executeRequest(input, options) {
        const operation = "path" in input ? OPERATION : "inspect_signal_decoders";
        let phase = "configuration";
        let capturedOutput;
        let resourcePath = "path" in input ? input.path : "sigrok decoder catalog";
        let effectiveLimits;
        let root;
        let result;
        try {
            if (options?.signal?.aborted)
                throw new AnalysisCancelledError(operation, {
                    cause: options.signal.reason,
                });
            await this.#resources.release();
            if (this.platform !== "linux")
                throw new Error("Signal decoding requires Linux with util-linux prlimit and PHXRE_SIGROK_COMMAND so expanded recordings are processed under an enforced address-space limit.");
            const configured = this.environment.PHXRE_SIGROK_COMMAND ?? "";
            if (!isAbsolute(configured))
                throw new Error("Supply absolute PHXRE_SIGROK_COMMAND for sigrok-cli 0.7.2 with libsigrokdecode.");
            const command = await realpath(configured);
            await access(command, constants.X_OK);
            const tool = await this.#resources.read(command, 64 * 1024 * 1024, options?.signal);
            const configuredLimiter = this.environment.PHXRE_SIGROK_PRLIMIT_COMMAND ?? "/usr/bin/prlimit";
            if (!isAbsolute(configuredLimiter))
                throw new Error("PHXRE_SIGROK_PRLIMIT_COMMAND must be absolute.");
            const limiter = await realpath(configuredLimiter);
            await access(limiter, constants.X_OK);
            const limiterIdentity = await this.#resources.read(limiter, 64 * 1024 * 1024, options?.signal);
            effectiveLimits = await this.#resources.readLimits(LIMITS);
            const limitArguments = prlimitArgumentVector(effectiveLimits, command);
            phase = "workspace";
            root = await this.createRuntime();
            this.#resources.retain(root, undefined);
            const snapshotPath = join(root.path, "recording");
            const execute = async (args, 
            // Caller selectors this command loads; their refusals are input errors.
            selection) => {
                capturedOutput = undefined;
                const output = await runOwnedCommand({
                    command: limiter,
                    arguments: [...limitArguments, ...args],
                    ...(root === undefined ? {} : { cwd: root.path }),
                    expectedCommand: null,
                    runId: `phxre-sigrok-${randomUUID()}`,
                    hostEnvironment: this.environment,
                }, {
                    timeoutMs: LIMITS.command_timeout_ms,
                    diagnosticBytes: LIMITS.output_bytes,
                    acceptNonZeroExit: true,
                }, {
                    ...(options?.signal === undefined
                        ? {}
                        : { signal: options.signal }),
                    ...(this.launcher === undefined ? {} : { launcher: this.launcher }),
                });
                capturedOutput = {
                    stdout: output.stdout.text,
                    stderr: output.stderr.text,
                    truncated: output.diagnosticTruncated ?? false,
                    exit_code: output.exitCode ?? null,
                    signal: output.signal ?? null,
                };
                // Finish bounded integrity checks after output; service handles late cancellation with Evidence.
                const previousPhase = phase;
                phase = "integrity";
                resourcePath = command;
                const current = await this.#resources.read(command, 64 * 1024 * 1024);
                resourcePath = limiter;
                const currentLimiter = await this.#resources.read(limiter, 64 * 1024 * 1024);
                if (currentLimiter.sha256 !== limiterIdentity.sha256)
                    throw new AnalysisArtifactChangedError(operation, limiter, "Configured resource limiter changed during analysis.", { capturedOutput });
                if (current.sha256 !== tool.sha256)
                    throw new AnalysisArtifactChangedError(operation, command, "Configured decoder executable changed during analysis.", { capturedOutput });
                phase = previousPhase;
                resourcePath = "path" in input ? input.path : command;
                const rejection = output.exitCode === 0 || selection === undefined
                    ? undefined
                    : parseSigrokSelectorRejection(output.stderr.text, selection);
                if (rejection !== undefined)
                    throw new AnalysisInputError(operation, { capturedOutput, userMessage: rejection.message }, [rejection]);
                if (output.exitCode !== 0)
                    throw new ProviderAdapterError(SIGROK_PROVIDER_IDENTITY.id, operation, {
                        diagnostics: {
                            exit_code: output.exitCode ?? null,
                            stdout: output.stdout.text,
                            stderr: output.stderr.text,
                        },
                    });
                return output;
            };
            phase = "configuration";
            const version = await execute(["--version"]);
            if (!/^sigrok-cli 0\.7\.2(?:\r?\n|$)/u.test(version.stdout.text) ||
                !version.stdout.text.includes("libsigrokdecode"))
                throw new Error("Expected sigrok-cli 0.7.2 with libsigrokdecode; inspect the selected installation.");
            const metadata = (args, diagnostics) => ({
                diagnostics,
                tool: {
                    configured_path: configured,
                    path: command,
                    sha256: tool.sha256,
                    version_banner: version.stdout.text,
                    version_diagnostics: version.stderr.text,
                    arguments: [...args],
                },
                resource_limiter: {
                    configured_path: configuredLimiter,
                    path: limiter,
                    sha256: limiterIdentity.sha256,
                    arguments: limitArguments,
                },
                limits: { ...LIMITS, ...effectiveLimits },
                hardware_acquisition: "not-performed",
            });
            if (!("path" in input)) {
                phase = "producer";
                const args = input.decoder === null
                    ? ["--dont-scan", "--list-supported"]
                    : ["--dont-scan", `--protocol-decoders=${input.decoder}`, "--show"];
                const output = await execute(args, input);
                const report = signalDecodersSchema.parse({
                    selection: input,
                    ...parseDecoderDiscovery(output.stdout.text, input),
                    ...metadata(args, output.stderr.text),
                });
                result = ok(createAnalysisExecution(report, SIGROK_PROVIDER_IDENTITY, {
                    subject: { path: command, sha256: tool.sha256, format: "file" },
                    limitations: [
                        "Catalog and help are observed from the selected sigrok installation. Help lines preserve producer descriptions, not a separately validated parameter schema.",
                        "Each request probes the installation again; pages do not share a frozen catalog. Decoder modules and libraries are trusted and not fully fingerprinted.",
                        "Hardware discovery, recording reads and acquisition are not requested. Linux per-process limits and bounded output apply; this is not an OS sandbox.",
                    ],
                }));
            }
            else {
                phase = "artifact";
                const selected = await this.#resources.read(input.path, LIMITS.input_bytes, options?.signal);
                phase = "workspace";
                await writeFile(snapshotPath, selected.bytes, {
                    flag: "wx",
                    mode: 0o400,
                });
                phase = "producer";
                const args = [
                    "--dont-scan",
                    "--input-file=recording",
                    `--protocol-decoders=${input.decoders}`,
                    "--protocol-decoder-samplenum",
                    ...(input.input_format === null
                        ? []
                        : [`--input-format=${input.input_format}`]),
                    ...(input.annotations === null
                        ? []
                        : [`--protocol-decoder-annotations=${input.annotations}`]),
                ];
                const output = await execute(args, input);
                phase = "integrity";
                resourcePath = snapshotPath;
                if ((await this.#resources.read(snapshotPath, LIMITS.input_bytes))
                    .sha256 !== selected.sha256)
                    throw new AnalysisArtifactChangedError(operation, snapshotPath, "Decoder changed the private recording copy.", capturedOutput === undefined ? {} : { capturedOutput });
                phase = "producer";
                resourcePath = "path" in input ? input.path : command;
                const report = signalRecordingSchema.parse({
                    artifact: {
                        path: input.path,
                        sha256: selected.sha256,
                        bytes: selected.bytes.length,
                    },
                    selection: input,
                    ...windowAnnotationText(output.stdout.text, input.line_offset, input.line_limit),
                    ...metadata(args, output.stderr.text),
                });
                result = ok(createAnalysisExecution(report, SIGROK_PROVIDER_IDENTITY, {
                    subject: {
                        path: input.path,
                        sha256: selected.sha256,
                        format: "file",
                    },
                    locations: [{ kind: "artifact-path", path: input.path }],
                    limitations: [
                        "Annotations are the selected decoder's interpretation of the recorded samples and caller-selected settings, not independently verified protocol semantics. Empty output does not establish absence of traffic.",
                        "Sample-number ranges and display text are preserved verbatim, not converted to timestamps or parsed as a lossless byte stream. All producer stderr is retained, including warnings on exit zero.",
                        "Only a private copy of the selected file is decoded. Hardware discovery/acquisition and target execution are not requested. Caller-supplied tools, plugins and decoder modules are trusted; this is not an OS sandbox.",
                        "Linux prlimit enforces soft and hard ceilings before execution, preserving stricter inherited limits: at most 1 GiB address space per process, 64 MiB per file, 30 CPU seconds and no core dumps. Effective limits are reported. Resident input is capped at 32 MiB, each command at 30 wall-clock seconds and combined output at 4 MiB. Output overflow fails. These are per-process/per-file limits, not aggregate memory or filesystem quotas; caller-supplied tools and the limiter are trusted.",
                    ],
                }));
            }
        }
        catch (cause) {
            if (root !== undefined &&
                cause instanceof OwnedCommandFailure &&
                cause.cleanupOwner !== undefined)
                this.#resources.retain(root, cause.cleanupOwner);
            result = err(this.#failure(cause, phase, resourcePath, root?.path ?? null, effectiveLimits, capturedOutput, operation));
        }
        return this.#resources.finish(result, (execution) => createEvidence(execution.subject ?? undefined, execution.provider, {
            operation,
            parameters: input,
            result: execution.result,
            confidence: "observed",
            locations: execution.locations,
            limitations: execution.limitations,
        }), operation, options?.signal);
    }
    #failure(cause, phase, path, workspacePath, effectiveLimits, observedOutput, operation = OPERATION) {
        if (cause instanceof AnalysisError)
            return cause;
        if (cause instanceof ArtifactReaderFailure && cause.cleanup !== undefined)
            return this.#resources.cleanupFailure(cause, (primary) => this.#failure(primary, phase, path, workspacePath, effectiveLimits, observedOutput, operation), observedOutput, operation);
        if (cause instanceof ArtifactReaderFailure && cause.reason === "cancelled")
            return new AnalysisCancelledError(operation, {
                cause: artifactFileCancellationCause(cause),
                ...(observedOutput === undefined
                    ? {}
                    : { capturedOutput: observedOutput }),
            });
        if (cause instanceof DecoderDiscoveryBudgetError)
            return new AnalysisResourceConstraintError(operation, "memory", cause.message, { line_budget: 65536 }, {
                cause,
                ...(observedOutput === undefined
                    ? {}
                    : { capturedOutput: observedOutput }),
                ...fixedAllowanceOptions("The sigrok decoder-discovery line allowance", "capture"),
            });
        const reason = cause instanceof Error ? cause.message : String(cause);
        if (cause instanceof OwnedCommandFailure)
            return this.#resources.commandFailure(cause, LIMITS, effectiveLimits, operation);
        if (phase === "workspace") {
            const code = cause instanceof Error &&
                "code" in cause &&
                typeof cause.code === "string"
                ? cause.code
                : null;
            if (code === "ENOSPC" || code === "EDQUOT" || code === "EFBIG")
                return new AnalysisResourceConstraintError(operation, "file-size", `Private analysis workspace failed (${code}): ${reason}`, { workspace_path: workspacePath, system_code: code }, { cause });
            return new ProviderAdapterError(SIGROK_PROVIDER_IDENTITY.id, operation, {
                cause,
                userMessage: `Cannot prepare the private analysis workspace: ${reason}`,
                diagnostics: {
                    stage: "workspace",
                    workspace_path: workspacePath,
                    system_code: code,
                    reason,
                },
            });
        }
        if (phase === "integrity") {
            const detail = {
                cause,
                ...(observedOutput === undefined
                    ? {}
                    : { capturedOutput: observedOutput }),
            };
            if (cause instanceof ArtifactReaderFailure &&
                ["limit", "integrity", "path"].includes(cause.reason))
                return new AnalysisArtifactChangedError(operation, path, `Post-run identity verification failed for ${path}: ${reason}`, detail);
            return new ProviderAdapterError(SIGROK_PROVIDER_IDENTITY.id, operation, {
                ...detail,
                diagnostics: { stage: "integrity", resource_path: path, reason },
            });
        }
        if (phase === "configuration")
            return new AnalysisCapabilityUnavailableError(SIGROK_PROVIDER_IDENTITY.id, operation, reason, {
                cause,
                ...(observedOutput === undefined
                    ? {}
                    : { capturedOutput: observedOutput }),
                userMessage: `${reason} On Linux, configure sigrok-cli 0.7.2 through PHXRE_SIGROK_COMMAND and util-linux prlimit through PHXRE_SIGROK_PRLIMIT_COMMAND (default /usr/bin/prlimit).`,
            });
        if (phase === "artifact" &&
            cause instanceof ArtifactReaderFailure &&
            cause.reason === "limit")
            return new AnalysisResourceConstraintError(operation, "file-size", reason, { input_bytes: LIMITS.input_bytes }, {
                cause,
                ...fixedAllowanceOptions("the fixed sigrok input allowance", "input"),
            });
        if (cause instanceof ArtifactReaderFailure && cause.reason === "integrity")
            return new AnalysisArtifactChangedError(operation, path, reason, {
                cause,
            });
        if (phase === "artifact" &&
            cause instanceof Error &&
            "code" in cause &&
            (cause.code === "EACCES" || cause.code === "EPERM"))
            return new AnalysisAccessDeniedError(operation, path, cause.code, {
                cause,
            });
        if (phase === "artifact")
            return new AnalysisInputError(operation, { cause }, [
                { path: ["path"], reason: "invalid_value", message: reason },
            ]);
        return new AnalysisOutputError(operation, reason, {
            cause,
            ...(observedOutput === undefined
                ? {}
                : { capturedOutput: observedOutput }),
        });
    }
}
